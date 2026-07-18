package spec

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults are v2's fully declarative execution defaults.
type Defaults struct {
	Become  *bool   `yaml:"become"`
	Timeout string  `yaml:"timeout,omitempty"`
	Action  *Action `yaml:"action"`
}
type Action struct {
	Mode          string   `yaml:"mode"`
	Authorization string   `yaml:"authorization,omitempty"`
	Cleanup       *Cleanup `yaml:"cleanup,omitempty"`
	ResidualRisk  string   `yaml:"residualRisk,omitempty"`
}
type Cleanup struct {
	Required bool    `yaml:"required"`
	Probe    string  `yaml:"probe,omitempty"`
	Expect   *Expect `yaml:"expect,omitempty"`
}
type SecretRef struct {
	Provider string `yaml:"provider"`
	Name     string `yaml:"name"`
}
type Input struct {
	Name       string     `yaml:"name"`
	Required   bool       `yaml:"required"`
	SecretRef  *SecretRef `yaml:"secretRef,omitempty"`
	Validation string     `yaml:"validation,omitempty"`
}
type Applicability struct {
	Always *bool       `yaml:"always,omitempty"`
	All    []Condition `yaml:"all,omitempty"`
	Any    []Condition `yaml:"any,omitempty"`
}
type Condition struct {
	Input      *InputCondition      `yaml:"input,omitempty"`
	Dependency *DependencyCondition `yaml:"dependency,omitempty"`
	Stage      *StageCondition      `yaml:"stage,omitempty"`
}
type InputCondition struct {
	Name     string  `yaml:"name"`
	Operator string  `yaml:"operator"`
	Value    *string `yaml:"value,omitempty"`
}
type DependencyCondition struct {
	Component string `yaml:"component"`
	State     string `yaml:"state"`
}
type StageCondition struct {
	In []string `yaml:"in"`
}

// ApplicabilityContext contains resolved, non-secret runtime facts. Values are
// deliberately strings: no template or shell expression is evaluated here.
type ApplicabilityContext struct {
	Inputs     map[string]string
	Components map[string]bool
	Stage      string
}

type ApplicabilityResult struct {
	Applicable bool
	Reason     string
}

// Platform declares one supported operating-system family and its versions.
type Platform struct {
	OS       string   `yaml:"os"`
	Versions []string `yaml:"versions"`
}

// EvidencePolicy controls non-secret output capture. Retention is interpreted
// by the evidence store; v2 parsing only validates the declared policy.
type EvidencePolicy struct {
	CaptureStdout *bool  `yaml:"captureStdout,omitempty"`
	Retention     string `yaml:"retention,omitempty"`
}

type v2Document struct {
	SchemaVersion int `yaml:"schemaVersion"`
	Compatibility struct {
		MinPilotVersion string `yaml:"minPilotVersion"`
	} `yaml:"compatibility"`
	Intent struct {
		Summary    string `yaml:"summary"`
		Source     string `yaml:"source"`
		Maintainer string `yaml:"maintainer"`
	} `yaml:"intent"`
	Targets struct {
		Roles     []string   `yaml:"roles"`
		HostScope string     `yaml:"hostScope,omitempty"`
		Platforms []Platform `yaml:"platforms,omitempty"`
		Hosts     []Host     `yaml:"hosts,omitempty"`
	} `yaml:"targets"`
	Inputs       []Input `yaml:"inputs"`
	Traceability struct {
		Components []string `yaml:"components"`
	} `yaml:"traceability"`
	Defaults       Defaults       `yaml:"defaults"`
	EvidencePolicy EvidencePolicy `yaml:"evidencePolicy,omitempty"`
}
type v2Check struct {
	ID          string         `yaml:"id"`
	Category    string         `yaml:"category"`
	Check       string         `yaml:"check"`
	Probe       string         `yaml:"probe"`
	Expect      Expect         `yaml:"expect"`
	Timeout     string         `yaml:"timeout,omitempty"`
	Scope       string         `yaml:"scope,omitempty"`
	Become      *bool          `yaml:"become,omitempty"`
	Action      *Action        `yaml:"action,omitempty"`
	AppliesWhen *Applicability `yaml:"appliesWhen,omitempty"`
	Tags        []string       `yaml:"tags,omitempty"`
	VerifyOnly  bool           `yaml:"verifyOnly,omitempty"`
	NeedsReview []string       `yaml:"needsReview,omitempty"`
}

func parseV2(raw []byte) (*Spec, error) {
	front, body, err := splitV2FrontMatter(raw)
	if err != nil {
		return nil, err
	}
	var doc v2Document
	if err := decodeStrictYAML(front, &doc); err != nil {
		return nil, fmt.Errorf("spec v2 front-matter: %w", err)
	}
	if doc.SchemaVersion != 2 {
		return nil, fmt.Errorf("spec v2: schemaVersion must be 2, got %d", doc.SchemaVersion)
	}
	if doc.Compatibility.MinPilotVersion == "" {
		return nil, fmt.Errorf("spec v2: compatibility.minPilotVersion is required")
	}
	if doc.Intent.Summary == "" || doc.Intent.Source == "" || doc.Intent.Maintainer == "" {
		return nil, fmt.Errorf("spec v2: intent.summary, intent.source, and intent.maintainer are required")
	}
	if len(doc.Targets.Roles) == 0 {
		return nil, fmt.Errorf("spec v2: targets.roles must not be empty")
	}
	if err := validateUniqueNames("target role", doc.Targets.Roles); err != nil {
		return nil, err
	}
	hostScope := doc.Targets.HostScope
	if hostScope == "" {
		hostScope = "per-host"
	}
	if hostScope != "per-host" && hostScope != "aggregate" {
		return nil, fmt.Errorf("spec v2: targets.hostScope must be per-host or aggregate")
	}
	for i, platform := range doc.Targets.Platforms {
		if platform.OS == "" || len(platform.Versions) == 0 {
			return nil, fmt.Errorf("spec v2 targets.platforms[%d]: os and versions are required", i)
		}
	}
	if doc.Defaults.Become == nil || doc.Defaults.Action == nil {
		return nil, fmt.Errorf("spec v2: defaults.become and defaults.action are required")
	}
	if err := validateAction(doc.Defaults.Action); err != nil {
		return nil, fmt.Errorf("spec v2 defaults.action: %w", err)
	}
	inputNames := make([]string, 0, len(doc.Inputs))
	for i := range doc.Inputs {
		if err := validateInput(doc.Inputs[i]); err != nil {
			return nil, fmt.Errorf("spec v2 inputs[%d]: %w", i, err)
		}
		inputNames = append(inputNames, doc.Inputs[i].Name)
	}
	if err := validateUniqueNames("input", inputNames); err != nil {
		return nil, err
	}
	if err := validateUniqueNames("traceability component", doc.Traceability.Components); err != nil {
		return nil, err
	}
	if doc.EvidencePolicy.Retention != "" && doc.EvidencePolicy.Retention != "default" && doc.EvidencePolicy.Retention != "retain-all" {
		return nil, fmt.Errorf("spec v2: evidencePolicy.retention must be default or retain-all")
	}
	checksRaw, err := v2ChecksBlock(body)
	if err != nil {
		return nil, err
	}
	var checks []v2Check
	if err := decodeStrictYAML(checksRaw, &checks); err != nil {
		return nil, fmt.Errorf("spec v2 checks: %w", err)
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("spec v2: checks must not be empty")
	}
	checkLines, err := v2CheckLines(checksRaw)
	if err != nil {
		return nil, err
	}
	s := &Spec{
		SchemaVersion:   2,
		Title:           "Verification Spec — " + doc.Intent.Summary,
		Maintainer:      doc.Intent.Maintainer,
		Alignment:       doc.Intent.Source,
		MinPilotVersion: doc.Compatibility.MinPilotVersion,
		Defaults:        doc.Defaults,
		Inputs:          doc.Inputs,
		Components:      doc.Traceability.Components,
		Roles:           doc.Targets.Roles,
		HostScope:       hostScope,
		Platforms:       doc.Targets.Platforms,
		EvidencePolicy:  doc.EvidencePolicy,
		Hosts:           doc.Targets.Hosts,
	}
	seen := map[string]struct{}{}
	for i, check := range checks {
		if !IDPattern.MatchString(check.ID) || check.Category == "" || check.Check == "" || check.Probe == "" {
			return nil, fmt.Errorf("spec v2 checks[%d]: id, category, check, and probe are required", i)
		}
		if _, ok := seen[check.ID]; ok {
			return nil, fmt.Errorf("spec v2: duplicate check id %q", check.ID)
		}
		seen[check.ID] = struct{}{}
		if err := validateExpect(check.Expect); err != nil {
			return nil, fmt.Errorf("spec v2 check %s expect: %w", check.ID, err)
		}
		action := check.Action
		if action == nil {
			action = doc.Defaults.Action
		}
		if err := validateAction(action); err != nil {
			return nil, fmt.Errorf("spec v2 check %s action: %w", check.ID, err)
		}
		if err := validateApplicability(check.AppliesWhen, doc.Inputs, doc.Traceability.Components); err != nil {
			return nil, fmt.Errorf("spec v2 check %s appliesWhen: %w", check.ID, err)
		}
		timeout := check.Timeout
		if timeout == "" {
			timeout = doc.Defaults.Timeout
		}
		var duration time.Duration
		if timeout != "" {
			duration, err = time.ParseDuration(timeout)
			if err != nil || duration <= 0 {
				return nil, fmt.Errorf("spec v2 check %s timeout: invalid duration %q", check.ID, timeout)
			}
		}
		become := check.Become
		if become == nil {
			become = doc.Defaults.Become
		}
		scope := check.Scope
		if scope == "" {
			scope = hostScope
		}
		if scope != "per-host" && scope != "aggregate" {
			return nil, fmt.Errorf("spec v2 check %s scope must be per-host or aggregate", check.ID)
		}
		if check.VerifyOnly && len(check.Tags) > 0 {
			return nil, fmt.Errorf("spec v2 check %s cannot set both tags and verifyOnly", check.ID)
		}
		if err := validateUniqueNames("check tag", check.Tags); err != nil {
			return nil, fmt.Errorf("spec v2 check %s: %w", check.ID, err)
		}
		if len(doc.Traceability.Components) == 0 && len(check.Tags) == 0 && !check.VerifyOnly {
			return nil, fmt.Errorf("spec v2 check %s: standalone spec requires tags or verifyOnly", check.ID)
		}
		s.Rows = append(s.Rows, Row{ID: check.ID, Category: check.Category, Check: check.Check, Expected: renderExpect(check.Expect), Command: check.Probe, Expect: check.Expect, Timeout: duration, Scope: scope, Become: become, Action: action, AppliesWhen: check.AppliesWhen, Tags: check.Tags, VerifyOnly: check.VerifyOnly, NeedsReview: check.NeedsReview, Line: checkLines[i]})
	}
	return s, nil
}

func splitV2FrontMatter(raw []byte) ([]byte, []byte, error) {
	lines := bytes.Split(raw, []byte("\n"))
	if len(lines) < 3 || strings.TrimSpace(string(lines[0])) != "---" {
		return nil, nil, fmt.Errorf("spec v2: front-matter must start with ---")
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(string(lines[i])) == "---" {
			return bytes.Join(lines[1:i], []byte("\n")), bytes.Join(lines[i+1:], []byte("\n")), nil
		}
	}
	return nil, nil, fmt.Errorf("spec v2: unterminated front-matter")
}
func decodeStrictYAML(raw []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}
func v2ChecksBlock(body []byte) ([]byte, error) {
	lines := strings.Split(string(body), "\n")
	section := false
	fenced := false
	found := false
	var out []string
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Checks"
			if fenced {
				return nil, fmt.Errorf("spec v2: unterminated checks YAML block")
			}
			continue
		}
		if !section {
			continue
		}
		if strings.TrimSpace(line) == "```yaml" {
			if fenced || found {
				return nil, fmt.Errorf("spec v2: multiple checks YAML blocks")
			}
			fenced = true
			found = true
			continue
		}
		if strings.TrimSpace(line) == "```" && fenced {
			fenced = false
			section = false
			continue
		}
		if fenced {
			out = append(out, line)
		}
	}
	if fenced {
		return nil, fmt.Errorf("spec v2: unterminated checks YAML block")
	}
	if found {
		return []byte(strings.Join(out, "\n")), nil
	}
	return nil, fmt.Errorf("spec v2: ## Checks must contain one fenced yaml block")
}

func v2CheckLines(raw []byte) ([]int, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("spec v2 checks line map: %w", err)
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("spec v2 checks must be a YAML sequence")
	}
	lines := make([]int, 0, len(node.Content[0].Content))
	for _, item := range node.Content[0].Content {
		lines = append(lines, item.Line)
	}
	return lines, nil
}

func validateUniqueNames(kind string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("spec v2: %s must not be empty", kind)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("spec v2: duplicate %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
func validateExpect(e Expect) error {
	if e.LegacyRCEcho != nil {
		return fmt.Errorf("legacyRC is not valid in v2")
	}
	if e.ExitCode == nil && e.Stdout == nil && e.Stderr == nil {
		return fmt.Errorf("at least one matcher is required")
	}
	if e.Stdout != nil {
		if err := validateStringMatcher(*e.Stdout); err != nil {
			return fmt.Errorf("stdout: %w", err)
		}
	}
	if e.Stderr != nil {
		if err := validateStringMatcher(*e.Stderr); err != nil {
			return fmt.Errorf("stderr: %w", err)
		}
	}
	return nil
}
func validateStringMatcher(m StringMatcher) error {
	n := 0
	if m.Equals != nil {
		n++
	}
	if m.Contains != nil {
		n++
	}
	if m.NotContains != nil {
		n++
	}
	if m.Regex != nil {
		n++
		if _, err := regexp.Compile(*m.Regex); err != nil {
			return err
		}
	}
	if n != 1 {
		return fmt.Errorf("exactly one predicate is required")
	}
	return nil
}
func validateAction(a *Action) error {
	if a == nil || (a.Mode != "readOnly" && a.Mode != "isolatedMutation") {
		return fmt.Errorf("mode must be readOnly or isolatedMutation")
	}
	if a.Mode == "readOnly" {
		if a.Authorization != "" || a.Cleanup != nil || a.ResidualRisk != "" {
			return fmt.Errorf("readOnly must not declare authorization, cleanup, or residualRisk")
		}
		return nil
	}
	if a.Authorization == "" || a.ResidualRisk == "" || a.Cleanup == nil || !a.Cleanup.Required || a.Cleanup.Probe == "" || a.Cleanup.Expect == nil {
		return fmt.Errorf("isolatedMutation requires authorization, residualRisk, cleanup.required=true, cleanup.probe, and cleanup.expect")
	}
	if err := validateExpect(*a.Cleanup.Expect); err != nil {
		return fmt.Errorf("cleanup.expect: %w", err)
	}
	return nil
}
func validateInput(in Input) error {
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(in.Name) {
		return fmt.Errorf("name must be an identifier")
	}
	if in.Validation != "" {
		if _, err := regexp.Compile(in.Validation); err != nil {
			return fmt.Errorf("validation: %w", err)
		}
	}
	if in.SecretRef != nil {
		if in.SecretRef.Provider != "ansibleVar" || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(in.SecretRef.Name) {
			return fmt.Errorf("secretRef must be an ansibleVar with a valid name")
		}
	}
	return nil
}
func validateApplicability(a *Applicability, inputs []Input, components []string) error {
	if a == nil {
		return nil
	}
	n := 0
	if a.Always != nil {
		n++
	}
	if a.All != nil {
		n++
	}
	if a.Any != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("must set exactly one of always, all, any")
	}
	if (a.All != nil && len(a.All) == 0) || (a.Any != nil && len(a.Any) == 0) {
		return fmt.Errorf("all/any must not be empty")
	}
	inputSet := map[string]struct{}{}
	for _, in := range inputs {
		inputSet[in.Name] = struct{}{}
	}
	componentSet := map[string]struct{}{}
	for _, component := range components {
		componentSet[component] = struct{}{}
	}
	conditions := a.All
	if a.Any != nil {
		conditions = a.Any
	}
	for _, condition := range conditions {
		if err := validateCondition(condition, inputSet, componentSet); err != nil {
			return err
		}
	}
	return nil
}
func validateCondition(c Condition, inputs, components map[string]struct{}) error {
	n := 0
	if c.Input != nil {
		n++
	}
	if c.Dependency != nil {
		n++
	}
	if c.Stage != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("each condition must set exactly one of input, dependency, stage")
	}
	if c.Input != nil {
		if _, ok := inputs[c.Input.Name]; !ok {
			return fmt.Errorf("input %q is not declared", c.Input.Name)
		}
		switch c.Input.Operator {
		case "set", "notSet", "equals", "notEquals":
		default:
			return fmt.Errorf("input operator %q is invalid", c.Input.Operator)
		}
		if (c.Input.Operator == "equals" || c.Input.Operator == "notEquals") && c.Input.Value == nil {
			return fmt.Errorf("input operator %s requires value", c.Input.Operator)
		}
		if (c.Input.Operator == "set" || c.Input.Operator == "notSet") && c.Input.Value != nil {
			return fmt.Errorf("input operator %s must not have value", c.Input.Operator)
		}
	}
	if c.Dependency != nil {
		if _, ok := components[c.Dependency.Component]; !ok {
			return fmt.Errorf("dependency component %q is not declared", c.Dependency.Component)
		}
		if c.Dependency.State != "selected" && c.Dependency.State != "notSelected" {
			return fmt.Errorf("dependency state %q is invalid", c.Dependency.State)
		}
	}
	if c.Stage != nil {
		if len(c.Stage.In) == 0 {
			return fmt.Errorf("stage.in must not be empty")
		}
		for _, stage := range c.Stage.In {
			if stage != "sandbox" && stage != "staging" && stage != "prod" {
				return fmt.Errorf("stage %q is invalid", stage)
			}
		}
	}
	return nil
}

// EvaluateApplicability returns false only for an explicitly false condition;
// malformed declarations were rejected by parseV2 and therefore cannot become
// an accidental skip at runtime.
func EvaluateApplicability(a *Applicability, ctx ApplicabilityContext) (ApplicabilityResult, error) {
	if a == nil || a.Always != nil {
		applicable := a == nil || *a.Always
		return ApplicabilityResult{Applicable: applicable, Reason: fmt.Sprintf("always=%t", applicable)}, nil
	}
	conditions := a.All
	all := true
	if a.Any != nil {
		conditions = a.Any
		all = false
	}
	matches := 0
	for i, condition := range conditions {
		matched, err := evaluateCondition(condition, ctx)
		if err != nil {
			return ApplicabilityResult{}, fmt.Errorf("condition[%d]: %w", i, err)
		}
		if matched {
			matches++
		}
	}
	if all {
		return ApplicabilityResult{Applicable: matches == len(conditions), Reason: fmt.Sprintf("all:%d/%d", matches, len(conditions))}, nil
	}
	return ApplicabilityResult{Applicable: matches > 0, Reason: fmt.Sprintf("any:%d/%d", matches, len(conditions))}, nil
}
func evaluateCondition(c Condition, ctx ApplicabilityContext) (bool, error) {
	if c.Input != nil {
		value, ok := ctx.Inputs[c.Input.Name]
		switch c.Input.Operator {
		case "set":
			return ok && value != "", nil
		case "notSet":
			return !ok || value == "", nil
		case "equals":
			return ok && value == *c.Input.Value, nil
		case "notEquals":
			return !ok || value != *c.Input.Value, nil
		}
	}
	if c.Dependency != nil {
		selected, ok := ctx.Components[c.Dependency.Component]
		if !ok {
			return false, fmt.Errorf("dependency selection for %q is unavailable", c.Dependency.Component)
		}
		return (c.Dependency.State == "selected" && selected) || (c.Dependency.State == "notSelected" && !selected), nil
	}
	if c.Stage != nil {
		if ctx.Stage == "" {
			return false, fmt.Errorf("stage is unavailable")
		}
		for _, stage := range c.Stage.In {
			if ctx.Stage == stage {
				return true, nil
			}
		}
	}
	return false, nil
}

// ValidateInputValues validates only non-secret values. Secrets are resolved
// by the unavailable v2 secret-aware runner and are rejected before probing.
func ValidateInputValues(inputs []Input, values map[string]string) error {
	for _, in := range inputs {
		if in.SecretRef != nil {
			continue
		}
		value, ok := values[in.Name]
		if in.Required && (!ok || value == "") {
			return fmt.Errorf("required input %q is not set", in.Name)
		}
		if ok && in.Validation != "" {
			re := regexp.MustCompile(in.Validation)
			if !re.MatchString(value) {
				return fmt.Errorf("input %q does not match validation", in.Name)
			}
		}
	}
	return nil
}
func renderExpect(e Expect) string {
	if e.ExitCode != nil && e.Stdout == nil && e.Stderr == nil {
		return fmt.Sprintf("exitCode: %d", *e.ExitCode)
	}
	return "typed"
}
