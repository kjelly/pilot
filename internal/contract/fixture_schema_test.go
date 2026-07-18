package contract

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/anomalyco/pilot/internal/spec"
)

// These private types retain repository/spec/tag traceability checks while the
// production loader owns strict YAML decoding and local schema validation.
type fixtureContract struct {
	SchemaVersion       int                 `yaml:"schemaVersion"`
	ID                  string              `yaml:"id"`
	Role                string              `yaml:"role"`
	Specs               []fixtureSpec       `yaml:"specs"`
	Playbooks           fixturePlaybooks    `yaml:"playbooks"`
	RegressionTests     []string            `yaml:"regressionTests"`
	Dependencies        []fixtureDependency `yaml:"dependencies"`
	Conflicts           []string            `yaml:"conflicts"`
	Bindings            []fixtureBinding    `yaml:"bindings"`
	OS                  []fixtureOS         `yaml:"os"`
	HostCardinality     string              `yaml:"hostCardinality"`
	Resources           fixtureResources    `yaml:"resources"`
	GroupVars           []fixtureGroupVar   `yaml:"groupVars"`
	InputRules          []fixtureInputRule  `yaml:"inputRules"`
	Endpoints           []fixtureEndpoint   `yaml:"endpoints"`
	StagePolicy         fixtureStagePolicy  `yaml:"stagePolicy"`
	Experimental        bool                `yaml:"experimental"`
	EvidenceRequirement fixtureEvidence     `yaml:"evidenceRequirement"`
	Lifecycle           fixtureLifecycle    `yaml:"lifecycle"`
	Traceability        fixtureTraceability `yaml:"traceability"`
	Verification        fixtureVerification `yaml:"verification"`
	Site                fixtureSite         `yaml:"site"`
}

type fixtureSpec struct {
	Path string             `yaml:"path"`
	Rows fixtureRowSelector `yaml:"rows"`
}

type fixtureRowSelector struct {
	All        bool     `yaml:"all"`
	IDs        []string `yaml:"ids"`
	Categories []string `yaml:"categories"`
}

type fixturePlaybooks struct {
	Apply        string  `yaml:"apply"`
	Rollback     *string `yaml:"rollback"`
	Upgrade      *string `yaml:"upgrade"`
	Decommission *string `yaml:"decommission"`
}

type fixtureDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
	Reason    string `yaml:"reason"`
}

type fixtureBinding struct {
	Input                          string             `yaml:"input"`
	RequiredWhenDependencySelected bool               `yaml:"requiredWhenDependencySelected"`
	SourceSelection                string             `yaml:"sourceSelection"`
	From                           fixtureBindingFrom `yaml:"from"`
}

type fixtureBindingFrom struct {
	Component string `yaml:"component"`
	Endpoint  string `yaml:"endpoint"`
}

type fixtureOS struct {
	Distro   string   `yaml:"distro"`
	Versions []string `yaml:"versions"`
}

type fixtureResources struct {
	MinCPU     int `yaml:"minCPU"`
	MinRAMMiB  int `yaml:"minRAMMiB"`
	MinDiskGiB int `yaml:"minDiskGiB"`
}

type fixtureGroupVar struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Required   bool   `yaml:"required"`
	Default    any    `yaml:"default"`
	Secret     bool   `yaml:"secret"`
	Validation string `yaml:"validation"`
}

type fixtureInputRule struct {
	All    []fixtureInputCondition `yaml:"all"`
	Any    []fixtureInputCondition `yaml:"any"`
	Reason string                  `yaml:"reason"`
}

type fixtureInputCondition struct {
	Input    string `yaml:"input"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

type fixtureEndpoint struct {
	Name   string `yaml:"name"`
	Scheme string `yaml:"scheme"`
	Port   int    `yaml:"port"`
	Path   string `yaml:"path"`
}

type fixtureStagePolicy struct {
	Variable string `yaml:"variable"`
	Default  string `yaml:"default"`
}

type fixtureEvidence struct {
	TargetTest  string `yaml:"targetTest"`
	Idempotency string `yaml:"idempotency"`
}

type fixtureLifecycle struct {
	Backup       *fixtureBackup `yaml:"backup"`
	Upgrade      any            `yaml:"upgrade"`
	Decommission any            `yaml:"decommission"`
}

type fixtureBackup struct {
	Provider string   `yaml:"provider"`
	PreHook  string   `yaml:"preHook"`
	Paths    []string `yaml:"paths"`
}

type fixtureTraceability struct {
	Mode       string                      `yaml:"mode"`
	Tag        *fixtureTagStrategy         `yaml:"tag"`
	Rows       map[string]fixtureRowTrace  `yaml:"rows"`
	Exemptions map[string]fixtureExemption `yaml:"exemptions"`
}

type fixtureVerification struct {
	AutoDeploy *bool `yaml:"autoDeploy"`
}

type fixtureTagStrategy struct {
	Kind   string `yaml:"kind"`
	Prefix string `yaml:"prefix"`
}

type fixtureRowTrace struct {
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type fixtureExemption struct {
	Kind   string   `yaml:"kind"`
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type fixtureSite struct {
	Include               bool              `yaml:"include"`
	Order                 int               `yaml:"order"`
	Vars                  map[string]string `yaml:"vars"`
	Tags                  []string          `yaml:"tags"`
	OptIn                 bool              `yaml:"optIn"`
	TargetGroupExpression *string           `yaml:"targetGroupExpression"`
}

type selectedFixtureSpec struct {
	Path string
	Rows []spec.Row
}

func TestFinalContractFixturesStrictAndSemanticallyValid(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	loader, err := NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(DefaultDirectory)
	if err != nil {
		t.Fatalf("production loader rejected final fixtures: %v", err)
	}
	if len(loaded) != 6 {
		t.Fatalf("production loader contract count = %d, want 6", len(loaded))
	}
	paths, err := filepath.Glob(filepath.Join(root, "docs", "tmp", "future", "contracts", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 {
		t.Fatalf("fixture count = %d, want 6", len(paths))
	}

	contracts := make([]fixtureContract, 0, len(paths))
	for _, path := range paths {
		contract := decodeFixtureContract(t, path)
		if err := validateFixtureContract(root, contract); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
		contracts = append(contracts, contract)
	}
	if err := validateFixtureSuite(root, contracts); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureSchemaRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "top level",
			yaml: minimalFixtureYAML() + "\nunknownTopLevel: true\n",
		},
		{
			name: "nested group var",
			yaml: strings.Replace(
				minimalFixtureYAML(),
				"groupVars: []",
				"groupVars:\n  - {name: x, required: false, secret: false, unknownNested: true}",
				1,
			),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var contract fixtureContract
			decoder := yaml.NewDecoder(strings.NewReader(tt.yaml))
			decoder.KnownFields(true)
			if err := decoder.Decode(&contract); err == nil {
				t.Fatal("strict decoder accepted unknown field")
			}
		})
	}
}

func TestFixtureSemanticValidationRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	docker := decodeFixtureContract(t, filepath.Join(root, "docs", "tmp", "future", "contracts", "docker.yaml"))
	freeIPA := decodeFixtureContract(t, filepath.Join(root, "docs", "tmp", "future", "contracts", "freeipa-server.yaml"))
	restic := decodeFixtureContract(t, filepath.Join(root, "docs", "tmp", "future", "contracts", "restic-backup.yaml"))

	tests := []struct {
		name    string
		mutate  func(*fixtureContract)
		wantErr string
		base    fixtureContract
	}{
		{
			name: "unknown schema version",
			base: docker,
			mutate: func(c *fixtureContract) {
				c.SchemaVersion = 2
			},
			wantErr: "schemaVersion 2",
		},
		{
			name: "selector uses more than one mode",
			base: docker,
			mutate: func(c *fixtureContract) {
				c.Specs[0].Rows.IDs = []string{"C1"}
			},
			wantErr: "must select exactly one of all, ids, or categories",
		},
		{
			name: "mapped traceability omits selected row",
			base: freeIPA,
			mutate: func(c *fixtureContract) {
				delete(c.Traceability.Rows, "docs/verification/freeipa-server.md#C1")
			},
			wantErr: "selected row docs/verification/freeipa-server.md#C1 has no mapped traceability or exemption",
		},
		{
			name: "binding input is undeclared",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.Bindings[0].Input = "missing_input"
			},
			wantErr: `binding input "missing_input" is not declared`,
		},
		{
			name: "binding component is not a dependency",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.Bindings[0].From.Component = "dashboard"
			},
			wantErr: `binding source component "dashboard" is not a declared dependency`,
		},
		{
			name: "dependency relation is required",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.Dependencies[0].Relation = ""
			},
			wantErr: `invalid dependency relation ""`,
		},
		{
			name: "binding source selection is required",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.Bindings[0].SourceSelection = ""
			},
			wantErr: `invalid binding sourceSelection ""`,
		},
		{
			name: "v1 fixture cannot enable auto deploy",
			base: docker,
			mutate: func(c *fixtureContract) {
				enabled := true
				c.Verification.AutoDeploy = &enabled
			},
			wantErr: "verification.autoDeploy requires Spec v2",
		},
		{
			name: "verification eligibility is required",
			base: docker,
			mutate: func(c *fixtureContract) {
				c.Verification = fixtureVerification{}
			},
			wantErr: "verification.autoDeploy is required",
		},
		{
			name: "input rule cannot reference unknown input",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.InputRules[0].Any[0].Input = "missing"
			},
			wantErr: `input rule references unknown group var "missing"`,
		},
		{
			name: "input rule is a strict union",
			base: restic,
			mutate: func(c *fixtureContract) {
				c.InputRules[0].All = c.InputRules[0].Any
			},
			wantErr: "input rule must select exactly one of all or any",
		},
		{
			name: "group var default must match declared type",
			base: restic,
			mutate: func(c *fixtureContract) {
				for i := range c.GroupVars {
					if c.GroupVars[i].Name == "restic_s3_port" {
						c.GroupVars[i].Default = "8333"
					}
				}
			},
			wantErr: `group var restic_s3_port default must be integer`,
		},
		{
			name: "derived exemption references absent tag",
			base: docker,
			mutate: func(c *fixtureContract) {
				rowRef := "docs/verification/docker.md#C3"
				exemption := c.Traceability.Exemptions[rowRef]
				exemption.Tags = []string{"docker-C999"}
				c.Traceability.Exemptions[rowRef] = exemption
			},
			wantErr: `tag "docker-C999" is absent`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			contract := cloneFixtureContract(t, tt.base)
			tt.mutate(&contract)
			err := validateFixtureContract(root, contract)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validation error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestFixtureSuiteRejectsDuplicateRowOwnership(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	dns := decodeFixtureContract(t, filepath.Join(root, "docs", "tmp", "future", "contracts", "dns.yaml"))
	duplicate := cloneFixtureContract(t, dns)
	duplicate.ID = "dns-duplicate"
	if err := validateFixtureSuite(root, []fixtureContract{dns, duplicate}); err == nil ||
		!strings.Contains(err.Error(), "owned by both dns and dns-duplicate") {
		t.Fatalf("suite validation error = %v, want duplicate ownership", err)
	}
}

func TestTraceabilityUsesQualifiedRowReferencesAcrossSpecs(t *testing.T) {
	t.Parallel()

	selected := []selectedFixtureSpec{
		{Path: "spec-a.md", Rows: []spec.Row{{ID: "C1"}}},
		{Path: "spec-b.md", Rows: []spec.Row{{ID: "C1"}}},
	}
	trace := fixtureTraceability{
		Mode: "mapped",
		Rows: map[string]fixtureRowTrace{
			"spec-a.md#C1": {Tags: []string{"feature-a"}, Reason: "spec A"},
			"spec-b.md#C1": {Tags: []string{"feature-b"}, Reason: "spec B"},
		},
	}
	tags := map[string]struct{}{"feature-a": {}, "feature-b": {}}
	if err := validateTraceability(trace, selected, tags); err != nil {
		t.Fatalf("qualified traceability rejected: %v", err)
	}

	delete(trace.Rows, "spec-b.md#C1")
	trace.Rows["C1"] = fixtureRowTrace{Tags: []string{"feature-b"}, Reason: "ambiguous"}
	if err := validateTraceability(trace, selected, tags); err == nil ||
		!strings.Contains(err.Error(), "spec-b.md#C1 has no mapped traceability") {
		t.Fatalf("unqualified row reference error = %v", err)
	}
}

func decodeFixtureContract(t *testing.T, path string) fixtureContract {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var contract fixtureContract
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("%s: strict decode: %v", filepath.Base(path), err)
	}
	return contract
}

func validateFixtureContract(root string, contract fixtureContract) error {
	if contract.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schemaVersion %d", contract.SchemaVersion)
	}
	if strings.TrimSpace(contract.ID) == "" || strings.TrimSpace(contract.Role) == "" {
		return fmt.Errorf("id and role are required")
	}
	if len(contract.Specs) == 0 {
		return fmt.Errorf("at least one spec is required")
	}
	if contract.Playbooks.Apply == "" {
		return fmt.Errorf("playbooks.apply is required")
	}
	applyPath := filepath.Join(root, contract.Playbooks.Apply)
	if err := requireRegularFile(applyPath); err != nil {
		return fmt.Errorf("apply playbook: %w", err)
	}
	for _, path := range contract.RegressionTests {
		if err := requireRegularFile(filepath.Join(root, path)); err != nil {
			return fmt.Errorf("regression test: %w", err)
		}
	}

	selectedSpecs, err := selectFixtureRows(root, contract.Specs)
	if err != nil {
		return err
	}
	tags, err := collectPlaybookTags(applyPath)
	if err != nil {
		return err
	}
	if err := validateTraceability(contract.Traceability, selectedSpecs, tags); err != nil {
		return err
	}
	if err := validateFixtureFields(contract); err != nil {
		return err
	}
	return nil
}

func validateFixtureFields(contract fixtureContract) error {
	switch contract.HostCardinality {
	case "exactly-one", "one-or-more", "zero-or-more":
	default:
		return fmt.Errorf("invalid hostCardinality %q", contract.HostCardinality)
	}
	if contract.Resources.MinCPU < 0 || contract.Resources.MinRAMMiB < 0 || contract.Resources.MinDiskGiB < 0 {
		return fmt.Errorf("resource minimums cannot be negative")
	}

	groupVars := make(map[string]fixtureGroupVar, len(contract.GroupVars))
	for _, groupVar := range contract.GroupVars {
		if groupVar.Name == "" {
			return fmt.Errorf("group var name is required")
		}
		if _, duplicate := groupVars[groupVar.Name]; duplicate {
			return fmt.Errorf("duplicate group var %q", groupVar.Name)
		}
		switch groupVar.Type {
		case "string", "stringList", "integer", "boolean", "duration":
		default:
			return fmt.Errorf("group var %s has invalid type %q", groupVar.Name, groupVar.Type)
		}
		if err := validateFixtureGroupVarDefault(groupVar); err != nil {
			return err
		}
		groupVars[groupVar.Name] = groupVar
		if groupVar.Validation != "" {
			if _, err := regexp.Compile(groupVar.Validation); err != nil {
				return fmt.Errorf("group var %s validation: %w", groupVar.Name, err)
			}
		}
	}
	for _, rule := range contract.InputRules {
		if rule.Reason == "" {
			return fmt.Errorf("input rule reason is required")
		}
		if (len(rule.All) > 0) == (len(rule.Any) > 0) {
			return fmt.Errorf("input rule must select exactly one of all or any")
		}
		conditions := rule.All
		if len(rule.Any) > 0 {
			conditions = rule.Any
		}
		for _, condition := range conditions {
			groupVar, ok := groupVars[condition.Input]
			if !ok {
				return fmt.Errorf("input rule references unknown group var %q", condition.Input)
			}
			switch condition.Operator {
			case "nonEmpty":
				if condition.Value != nil {
					return fmt.Errorf("input rule operator nonEmpty cannot have value")
				}
				if groupVar.Type != "string" && groupVar.Type != "stringList" {
					return fmt.Errorf("input rule operator nonEmpty requires string or stringList input")
				}
			case "equals", "notEquals":
				if condition.Value == nil {
					return fmt.Errorf("input rule operator %s requires value", condition.Operator)
				}
			case "contains", "notContains":
				if groupVar.Type != "string" {
					return fmt.Errorf("input rule operator %s requires string input", condition.Operator)
				}
				if _, ok := condition.Value.(string); !ok {
					return fmt.Errorf("input rule operator %s requires string value", condition.Operator)
				}
			default:
				return fmt.Errorf("input rule has invalid operator %q", condition.Operator)
			}
		}
	}

	dependencies := make(map[string]fixtureDependency, len(contract.Dependencies))
	for _, dependency := range contract.Dependencies {
		if dependency.Component == "" {
			return fmt.Errorf("dependency component is required")
		}
		if _, duplicate := dependencies[dependency.Component]; duplicate {
			return fmt.Errorf("duplicate dependency %q", dependency.Component)
		}
		switch dependency.Relation {
		case "sameHosts", "providerEndpoint":
		case "planOnly":
			if dependency.Reason == "" {
				return fmt.Errorf("planOnly dependency %q requires reason", dependency.Component)
			}
		default:
			return fmt.Errorf("invalid dependency relation %q", dependency.Relation)
		}
		dependencies[dependency.Component] = dependency
	}
	for _, binding := range contract.Bindings {
		input, ok := groupVars[binding.Input]
		if !ok {
			return fmt.Errorf("binding input %q is not declared in groupVars", binding.Input)
		}
		dependency, ok := dependencies[binding.From.Component]
		if !ok {
			return fmt.Errorf("binding source component %q is not a declared dependency", binding.From.Component)
		}
		if dependency.Relation != "providerEndpoint" {
			return fmt.Errorf("binding source component %q must use providerEndpoint relation", binding.From.Component)
		}
		if binding.From.Endpoint == "" {
			return fmt.Errorf("binding source endpoint is required")
		}
		switch binding.SourceSelection {
		case "exactlyOne", "explicit":
			if input.Type != "string" {
				return fmt.Errorf("binding input %q must be string for %s selection", binding.Input, binding.SourceSelection)
			}
		case "all":
			if input.Type != "stringList" {
				return fmt.Errorf("binding input %q must be stringList for all selection", binding.Input)
			}
		default:
			return fmt.Errorf("invalid binding sourceSelection %q", binding.SourceSelection)
		}
	}
	for _, dependency := range dependencies {
		if dependency.Relation != "providerEndpoint" {
			continue
		}
		found := false
		for _, binding := range contract.Bindings {
			if binding.From.Component == dependency.Component {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("providerEndpoint dependency %q requires a binding", dependency.Component)
		}
	}

	endpoints := make(map[string]struct{}, len(contract.Endpoints))
	for _, endpoint := range contract.Endpoints {
		if endpoint.Name == "" || endpoint.Scheme == "" {
			return fmt.Errorf("endpoint name and scheme are required")
		}
		if _, duplicate := endpoints[endpoint.Name]; duplicate {
			return fmt.Errorf("duplicate endpoint %q", endpoint.Name)
		}
		endpoints[endpoint.Name] = struct{}{}
		if endpoint.Scheme == "unix" {
			if endpoint.Path == "" || endpoint.Port != 0 {
				return fmt.Errorf("unix endpoint %s must set path and omit port", endpoint.Name)
			}
		} else if endpoint.Port <= 0 {
			return fmt.Errorf("network endpoint %s must set a positive port", endpoint.Name)
		}
	}

	if contract.StagePolicy.Variable == "" || contract.StagePolicy.Default == "" {
		return fmt.Errorf("stagePolicy variable and default are required")
	}
	switch contract.EvidenceRequirement.TargetTest {
	case "vm", "vm-or-docker", "topology":
	default:
		return fmt.Errorf("invalid evidence targetTest %q", contract.EvidenceRequirement.TargetTest)
	}
	if contract.EvidenceRequirement.Idempotency != "required" {
		return fmt.Errorf("invalid evidence idempotency %q", contract.EvidenceRequirement.Idempotency)
	}
	if contract.Site.Include && contract.Site.Order <= 0 {
		return fmt.Errorf("included site projection must have a positive order")
	}
	if contract.Verification.AutoDeploy == nil {
		return fmt.Errorf("verification.autoDeploy is required")
	}
	if *contract.Verification.AutoDeploy {
		return fmt.Errorf("verification.autoDeploy requires Spec v2; final schema fixtures still reference v1 specs")
	}
	return nil
}

func validateFixtureGroupVarDefault(groupVar fixtureGroupVar) error {
	if groupVar.Default == nil {
		return nil
	}
	switch groupVar.Type {
	case "string":
		if _, ok := groupVar.Default.(string); !ok {
			return fmt.Errorf("group var %s default must be string", groupVar.Name)
		}
	case "stringList":
		values, ok := groupVar.Default.([]any)
		if !ok {
			return fmt.Errorf("group var %s default must be stringList", groupVar.Name)
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("group var %s default must be stringList", groupVar.Name)
			}
		}
	case "integer":
		if _, ok := groupVar.Default.(int); !ok {
			return fmt.Errorf("group var %s default must be integer", groupVar.Name)
		}
	case "boolean":
		if _, ok := groupVar.Default.(bool); !ok {
			return fmt.Errorf("group var %s default must be boolean", groupVar.Name)
		}
	case "duration":
		value, ok := groupVar.Default.(string)
		if !ok {
			return fmt.Errorf("group var %s default must be duration string", groupVar.Name)
		}
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("group var %s default must be Go duration: %w", groupVar.Name, err)
		}
	}
	return nil
}

func selectFixtureRows(root string, entries []fixtureSpec) ([]selectedFixtureSpec, error) {
	out := make([]selectedFixtureSpec, 0, len(entries))
	for _, entry := range entries {
		if err := requireRegularFile(filepath.Join(root, entry.Path)); err != nil {
			return nil, fmt.Errorf("spec: %w", err)
		}
		modes := 0
		if entry.Rows.All {
			modes++
		}
		if len(entry.Rows.IDs) > 0 {
			modes++
		}
		if len(entry.Rows.Categories) > 0 {
			modes++
		}
		if modes != 1 {
			return nil, fmt.Errorf("spec %s rows must select exactly one of all, ids, or categories", entry.Path)
		}
		parsed, err := spec.Parse(filepath.Join(root, entry.Path))
		if err != nil {
			return nil, fmt.Errorf("parse spec %s: %w", entry.Path, err)
		}
		selected := make([]spec.Row, 0, len(parsed.Rows))
		idSet := stringSliceSet(entry.Rows.IDs)
		categorySet := stringSliceSet(entry.Rows.Categories)
		for _, row := range parsed.Rows {
			if entry.Rows.All {
				selected = append(selected, row)
				continue
			}
			if _, ok := idSet[row.ID]; ok {
				selected = append(selected, row)
				delete(idSet, row.ID)
			}
			if _, ok := categorySet[row.Category]; ok {
				selected = append(selected, row)
			}
		}
		if len(idSet) > 0 {
			return nil, fmt.Errorf("spec %s selector references unknown row IDs: %s", entry.Path, strings.Join(sortedKeys(idSet), ", "))
		}
		for category := range categorySet {
			found := false
			for _, row := range selected {
				if row.Category == category {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("spec %s selector references unknown category %q", entry.Path, category)
			}
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("spec %s selector selected zero rows", entry.Path)
		}
		out = append(out, selectedFixtureSpec{Path: entry.Path, Rows: selected})
	}
	return out, nil
}

func validateTraceability(trace fixtureTraceability, specs []selectedFixtureSpec, tags map[string]struct{}) error {
	selected := make(map[string]spec.Row)
	for _, selectedSpec := range specs {
		for _, row := range selectedSpec.Rows {
			selected[selectedSpec.Path+"#"+row.ID] = row
		}
	}
	for rowRef := range trace.Exemptions {
		if _, ok := selected[rowRef]; !ok {
			return fmt.Errorf("traceability exemption references unselected row %s", rowRef)
		}
	}

	switch trace.Mode {
	case "rowTags":
		if trace.Tag == nil {
			return fmt.Errorf("rowTags mode requires tag strategy")
		}
		for rowRef, row := range selected {
			if exemption, ok := trace.Exemptions[rowRef]; ok {
				if err := validateExemption(rowRef, exemption, tags); err != nil {
					return err
				}
				continue
			}
			var tag string
			switch trace.Tag.Kind {
			case "bare":
				if trace.Tag.Prefix != "" {
					return fmt.Errorf("bare row tag strategy cannot set prefix")
				}
				tag = row.ID
			case "rolePrefixed":
				if trace.Tag.Prefix == "" {
					return fmt.Errorf("rolePrefixed row tag strategy requires prefix")
				}
				tag = trace.Tag.Prefix + "-" + row.ID
			default:
				return fmt.Errorf("unknown row tag strategy %q", trace.Tag.Kind)
			}
			if _, ok := tags[tag]; !ok {
				return fmt.Errorf("selected row %s tag %q is absent from apply playbook", rowRef, tag)
			}
		}
	case "mapped":
		for rowRef := range selected {
			if exemption, ok := trace.Exemptions[rowRef]; ok {
				if err := validateExemption(rowRef, exemption, tags); err != nil {
					return err
				}
				continue
			}
			mapping, ok := trace.Rows[rowRef]
			if !ok {
				return fmt.Errorf("selected row %s has no mapped traceability or exemption", rowRef)
			}
			if mapping.Reason == "" || len(mapping.Tags) == 0 {
				return fmt.Errorf("mapped row %s requires tags and reason", rowRef)
			}
			for _, tag := range mapping.Tags {
				if _, ok := tags[tag]; !ok {
					return fmt.Errorf("mapped row %s tag %q is absent from apply playbook", rowRef, tag)
				}
			}
		}
		for rowRef := range trace.Rows {
			if _, ok := selected[rowRef]; !ok {
				return fmt.Errorf("mapped traceability references unselected row %s", rowRef)
			}
		}
	default:
		return fmt.Errorf("unknown traceability mode %q", trace.Mode)
	}
	return nil
}

func validateExemption(rowRef string, exemption fixtureExemption, tags map[string]struct{}) error {
	if exemption.Reason == "" {
		return fmt.Errorf("row %s exemption requires reason", rowRef)
	}
	switch exemption.Kind {
	case "verifyOnly":
		if len(exemption.Tags) != 0 {
			return fmt.Errorf("verifyOnly row %s cannot reference apply tags", rowRef)
		}
	case "derived":
		if len(exemption.Tags) == 0 {
			return fmt.Errorf("derived row %s requires apply tags", rowRef)
		}
		for _, tag := range exemption.Tags {
			if _, ok := tags[tag]; !ok {
				return fmt.Errorf("derived row %s tag %q is absent from apply playbook", rowRef, tag)
			}
		}
	default:
		return fmt.Errorf("row %s has unknown exemption kind %q", rowRef, exemption.Kind)
	}
	return nil
}

func validateFixtureSuite(root string, contracts []fixtureContract) error {
	ids := make(map[string]struct{}, len(contracts))
	owners := make(map[string]string)
	for _, contract := range contracts {
		if _, duplicate := ids[contract.ID]; duplicate {
			return fmt.Errorf("duplicate component id %q", contract.ID)
		}
		ids[contract.ID] = struct{}{}
		selectedSpecs, err := selectFixtureRows(root, contract.Specs)
		if err != nil {
			return err
		}
		for _, selectedSpec := range selectedSpecs {
			for _, row := range selectedSpec.Rows {
				key := selectedSpec.Path + "#" + row.ID
				if owner, duplicate := owners[key]; duplicate {
					return fmt.Errorf("spec row %s is owned by both %s and %s", key, owner, contract.ID)
				}
				owners[key] = contract.ID
			}
		}
	}
	return nil
}

func collectPlaybookTags(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse playbook tags: %w", err)
	}
	tags := make(map[string]struct{})
	collectTagsFromNode(&root, tags)
	return tags, nil
}

func collectTagsFromNode(node *yaml.Node, tags map[string]struct{}) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "tags" {
				switch value.Kind {
				case yaml.SequenceNode:
					for _, tag := range value.Content {
						tags[tag.Value] = struct{}{}
					}
				case yaml.ScalarNode:
					tags[value.Value] = struct{}{}
				}
			}
			collectTagsFromNode(value, tags)
		}
		return
	}
	for _, child := range node.Content {
		collectTagsFromNode(child, tags)
	}
}

func cloneFixtureContract(t *testing.T, contract fixtureContract) fixtureContract {
	t.Helper()
	data, err := yaml.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	var clone fixtureContract
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

func stringSliceSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func minimalFixtureYAML() string {
	return `schemaVersion: 1
id: minimal
role: minimal
specs: []
playbooks: {}
regressionTests: []
dependencies: []
conflicts: []
bindings: []
os: []
hostCardinality: one-or-more
resources: {}
groupVars: []
inputRules: []
endpoints: []
stagePolicy: {}
experimental: false
evidenceRequirement: {}
lifecycle: {}
traceability: {}
verification: {autoDeploy: false}
site: {}`
}
