// Package contract loads and validates versioned delivery component contracts.
package contract

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the ComponentContract schema version supported by this loader.
const SchemaVersion = 1

// Contract is the versioned, machine-readable description of one delivery component.
type Contract struct {
	SchemaVersion       int          `yaml:"schemaVersion"`
	ID                  string       `yaml:"id"`
	Role                string       `yaml:"role"`
	Specs               []Spec       `yaml:"specs"`
	Playbooks           Playbooks    `yaml:"playbooks"`
	RegressionTests     []string     `yaml:"regressionTests"`
	Dependencies        []Dependency `yaml:"dependencies"`
	Conflicts           []string     `yaml:"conflicts"`
	Bindings            []Binding    `yaml:"bindings"`
	OS                  []OS         `yaml:"os"`
	HostCardinality     string       `yaml:"hostCardinality"`
	Resources           Resources    `yaml:"resources"`
	GroupVars           []GroupVar   `yaml:"groupVars"`
	InputRules          []InputRule  `yaml:"inputRules"`
	Endpoints           []Endpoint   `yaml:"endpoints"`
	StagePolicy         StagePolicy  `yaml:"stagePolicy"`
	Experimental        bool         `yaml:"experimental"`
	EvidenceRequirement Evidence     `yaml:"evidenceRequirement"`
	Lifecycle           Lifecycle    `yaml:"lifecycle"`
	Traceability        Traceability `yaml:"traceability"`
	Verification        Verification `yaml:"verification"`
	Site                Site         `yaml:"site"`
}

// Spec selects verification rows owned by this component.
type Spec struct {
	Path string      `yaml:"path"`
	Rows RowSelector `yaml:"rows"`
}

// RowSelector selects all rows, row IDs, or categories from one spec.
type RowSelector struct {
	All        bool     `yaml:"all"`
	IDs        []string `yaml:"ids"`
	Categories []string `yaml:"categories"`
}

// Playbooks lists the component lifecycle playbooks.
type Playbooks struct {
	Apply        string  `yaml:"apply"`
	Rollback     *string `yaml:"rollback"`
	Upgrade      *string `yaml:"upgrade"`
	Decommission *string `yaml:"decommission"`
}

// Dependency describes a component dependency and its placement relation.
type Dependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
	Reason    string `yaml:"reason"`
}

// Binding maps a provider endpoint to one component input.
type Binding struct {
	Input                          string      `yaml:"input"`
	RequiredWhenDependencySelected bool        `yaml:"requiredWhenDependencySelected"`
	SourceSelection                string      `yaml:"sourceSelection"`
	From                           BindingFrom `yaml:"from"`
}

// BindingFrom identifies the provider component endpoint for a binding.
type BindingFrom struct {
	Component string `yaml:"component"`
	Endpoint  string `yaml:"endpoint"`
}

// OS identifies one supported distribution and version set.
type OS struct {
	Distro   string   `yaml:"distro"`
	Versions []string `yaml:"versions"`
}

// Resources defines minimum host resources for a component.
type Resources struct {
	MinCPU     int `yaml:"minCPU"`
	MinRAMMiB  int `yaml:"minRAMMiB"`
	MinDiskGiB int `yaml:"minDiskGiB"`
}

// GroupVar declares one typed component input or vault-backed variable.
type GroupVar struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Required   bool   `yaml:"required"`
	Default    any    `yaml:"default"`
	Secret     bool   `yaml:"secret"`
	Validation string `yaml:"validation"`
}

// InputRule expresses an all/any cross-input preflight requirement.
type InputRule struct {
	All    []InputCondition `yaml:"all"`
	Any    []InputCondition `yaml:"any"`
	Reason string           `yaml:"reason"`
}

// InputCondition evaluates one named input within an InputRule.
type InputCondition struct {
	Input    string `yaml:"input"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

// Endpoint describes a network or Unix-socket endpoint provided by a component.
type Endpoint struct {
	Name   string `yaml:"name"`
	Scheme string `yaml:"scheme"`
	Port   int    `yaml:"port"`
	Path   string `yaml:"path"`
}

// StagePolicy names the stage variable and its default.
type StagePolicy struct {
	Variable string `yaml:"variable"`
	Default  string `yaml:"default"`
}

// Evidence declares the actual-run evidence required for a component.
type Evidence struct {
	TargetTest  string `yaml:"targetTest"`
	Idempotency string `yaml:"idempotency"`
}

// Lifecycle records data-handling policy that is not an executable playbook path.
type Lifecycle struct {
	Backup       *Backup `yaml:"backup"`
	Upgrade      any     `yaml:"upgrade"`
	Decommission any     `yaml:"decommission"`
}

// Backup describes a component backup policy.
type Backup struct {
	Provider string   `yaml:"provider"`
	PreHook  string   `yaml:"preHook"`
	Paths    []string `yaml:"paths"`
}

// Traceability maps owned verification rows to apply tags or exemptions.
type Traceability struct {
	Mode       string               `yaml:"mode"`
	Tag        *TagStrategy         `yaml:"tag"`
	Rows       map[string]RowTrace  `yaml:"rows"`
	Exemptions map[string]Exemption `yaml:"exemptions"`
}

// TagStrategy derives a row tag from a verification row ID.
type TagStrategy struct {
	Kind   string `yaml:"kind"`
	Prefix string `yaml:"prefix"`
}

// RowTrace explicitly maps one verification row to apply tags.
type RowTrace struct {
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

// Exemption records why a verification row has no direct apply tag.
type Exemption struct {
	Kind   string   `yaml:"kind"`
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

// Verification controls deploy-time verification eligibility.
type Verification struct {
	AutoDeploy *bool `yaml:"autoDeploy"`
}

// Site is the lint-only projection of a component into the hand-written site playbook.
type Site struct {
	Include               bool              `yaml:"include"`
	Order                 int               `yaml:"order"`
	Vars                  map[string]string `yaml:"vars"`
	Tags                  []string          `yaml:"tags"`
	OptIn                 bool              `yaml:"optIn"`
	TargetGroupExpression *string           `yaml:"targetGroupExpression"`
}

// Loader confines contract reads to Root and rejects unknown YAML fields.
type Loader struct {
	Root string
}

// Catalog is an immutable lookup view over a loaded component contract set.
type Catalog struct {
	contracts []Contract
	byID      map[string]int
}

// NewLoader returns a loader rooted at an absolute repository directory.
func NewLoader(root string) (Loader, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Loader{}, fmt.Errorf("resolve contract root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return Loader{}, fmt.Errorf("stat contract root: %w", err)
	}
	if !info.IsDir() {
		return Loader{}, fmt.Errorf("contract root %s is not a directory", absRoot)
	}
	return Loader{Root: absRoot}, nil
}

// LoadFile loads one repository-relative contract file and validates its local schema.
func (l Loader) LoadFile(path string) (Contract, error) {
	absPath, err := l.resolve(path)
	if err != nil {
		return Contract{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Contract{}, fmt.Errorf("read contract %s: %w", path, err)
	}
	var contract Contract
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode contract %s: %w", path, err)
	}
	if err := validateLocal(contract); err != nil {
		return Contract{}, fmt.Errorf("validate contract %s: %w", path, err)
	}
	if err := l.validateAutoDeploySpecs(contract); err != nil {
		return Contract{}, fmt.Errorf("validate contract %s: %w", path, err)
	}
	return contract, nil
}

// LoadDir loads every .yaml contract in a repository-relative directory in stable order.
func (l Loader) LoadDir(dir string) ([]Contract, error) {
	absDir, err := l.resolve(dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("read contract directory %s: %w", dir, err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("contract directory %s contains no .yaml files", dir)
	}
	contracts := make([]Contract, 0, len(paths))
	ids := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		contract, err := l.LoadFile(path)
		if err != nil {
			return nil, err
		}
		if _, exists := ids[contract.ID]; exists {
			return nil, fmt.Errorf("duplicate component id %q", contract.ID)
		}
		ids[contract.ID] = struct{}{}
		contracts = append(contracts, contract)
	}
	return contracts, nil
}

// LoadCatalog loads a contract directory and returns lookup helpers over it.
func (l Loader) LoadCatalog(dir string) (Catalog, error) {
	contracts, err := l.LoadDir(dir)
	if err != nil {
		return Catalog{}, err
	}
	return NewCatalog(contracts)
}

// NewCatalog validates unique component IDs and builds lookup indexes.
func NewCatalog(contracts []Contract) (Catalog, error) {
	if len(contracts) == 0 {
		return Catalog{}, fmt.Errorf("contract catalog is empty")
	}
	copyOfContracts := append([]Contract(nil), contracts...)
	byID := make(map[string]int, len(copyOfContracts))
	for i, contract := range copyOfContracts {
		if _, exists := byID[contract.ID]; exists {
			return Catalog{}, fmt.Errorf("duplicate component id %q", contract.ID)
		}
		byID[contract.ID] = i
	}
	return Catalog{contracts: copyOfContracts, byID: byID}, nil
}

// Component returns the contract with id, if present.
func (c Catalog) Component(id string) (Contract, bool) {
	index, ok := c.byID[id]
	if !ok {
		return Contract{}, false
	}
	return c.contracts[index], true
}

// ComponentsForRole returns every component whose primary role matches role.
func (c Catalog) ComponentsForRole(role string) []Contract {
	components := make([]Contract, 0)
	for _, contract := range c.contracts {
		if contract.Role == role {
			components = append(components, contract)
		}
	}
	return components
}

func (l Loader) resolve(path string) (string, error) {
	if l.Root == "" {
		return "", fmt.Errorf("contract loader root is empty")
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("contract path must be relative: %s", path)
	}
	absPath := filepath.Clean(filepath.Join(l.Root, path))
	rel, err := filepath.Rel(l.Root, absPath)
	if err != nil {
		return "", fmt.Errorf("resolve contract path %s: %w", path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("contract path escapes root: %s", path)
	}
	return absPath, nil
}

func (l Loader) validateAutoDeploySpecs(contract Contract) error {
	if contract.Verification.AutoDeploy == nil || !*contract.Verification.AutoDeploy {
		return nil
	}
	for _, entry := range contract.Specs {
		path, err := l.resolve(entry.Path)
		if err != nil {
			return fmt.Errorf("autoDeploy spec %s: %w", entry.Path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("autoDeploy spec %s: %w", entry.Path, err)
		}
		if !isSpecV2(data) {
			return fmt.Errorf("verification.autoDeploy requires Spec v2: %s", entry.Path)
		}
	}
	return nil
}

func isSpecV2(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "---" {
		return false
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return false
	}
	var frontMatter struct {
		SchemaVersion int `yaml:"schemaVersion"`
	}
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end], "\n")), &frontMatter); err != nil {
		return false
	}
	return frontMatter.SchemaVersion == 2
}

func validateLocal(contract Contract) error {
	if contract.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %d", contract.SchemaVersion)
	}
	if strings.TrimSpace(contract.ID) == "" || strings.TrimSpace(contract.Role) == "" {
		return fmt.Errorf("id and role are required")
	}
	if len(contract.Specs) == 0 {
		return fmt.Errorf("at least one spec is required")
	}
	for _, entry := range contract.Specs {
		if strings.TrimSpace(entry.Path) == "" {
			return fmt.Errorf("spec path is required")
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
			return fmt.Errorf("spec %s rows must select exactly one of all, ids, or categories", entry.Path)
		}
	}
	if strings.TrimSpace(contract.Playbooks.Apply) == "" {
		return fmt.Errorf("playbooks.apply is required")
	}
	switch contract.HostCardinality {
	case "exactly-one", "one-or-more", "zero-or-more":
	default:
		return fmt.Errorf("invalid hostCardinality %q", contract.HostCardinality)
	}
	if contract.Resources.MinCPU < 0 || contract.Resources.MinRAMMiB < 0 || contract.Resources.MinDiskGiB < 0 {
		return fmt.Errorf("resource minimums cannot be negative")
	}
	if err := validateGroupVars(contract.GroupVars, contract.InputRules); err != nil {
		return err
	}
	if err := validateDependenciesAndBindings(contract.Dependencies, contract.Bindings, contract.GroupVars); err != nil {
		return err
	}
	if err := validateEndpoints(contract.Endpoints); err != nil {
		return err
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
	return nil
}

func validateGroupVars(groupVars []GroupVar, rules []InputRule) error {
	known := make(map[string]GroupVar, len(groupVars))
	for _, groupVar := range groupVars {
		if groupVar.Name == "" {
			return fmt.Errorf("group var name is required")
		}
		if _, exists := known[groupVar.Name]; exists {
			return fmt.Errorf("duplicate group var %q", groupVar.Name)
		}
		switch groupVar.Type {
		case "string", "stringList", "integer", "boolean", "duration":
		default:
			return fmt.Errorf("group var %s has invalid type %q", groupVar.Name, groupVar.Type)
		}
		if err := validateDefault(groupVar); err != nil {
			return err
		}
		if groupVar.Validation != "" {
			if _, err := regexp.Compile(groupVar.Validation); err != nil {
				return fmt.Errorf("group var %s validation: %w", groupVar.Name, err)
			}
		}
		known[groupVar.Name] = groupVar
	}
	return validateInputRules(rules, known)
}

func validateDefault(groupVar GroupVar) error {
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

func validateInputRules(rules []InputRule, known map[string]GroupVar) error {
	for _, rule := range rules {
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
			groupVar, ok := known[condition.Input]
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
	return nil
}

func validateDependenciesAndBindings(dependencies []Dependency, bindings []Binding, groupVars []GroupVar) error {
	knownVars := make(map[string]GroupVar, len(groupVars))
	for _, groupVar := range groupVars {
		knownVars[groupVar.Name] = groupVar
	}
	knownDependencies := make(map[string]Dependency, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.Component == "" {
			return fmt.Errorf("dependency component is required")
		}
		if _, exists := knownDependencies[dependency.Component]; exists {
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
		knownDependencies[dependency.Component] = dependency
	}
	for _, binding := range bindings {
		input, ok := knownVars[binding.Input]
		if !ok {
			return fmt.Errorf("binding input %q is not declared in groupVars", binding.Input)
		}
		dependency, ok := knownDependencies[binding.From.Component]
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
	for _, dependency := range knownDependencies {
		if dependency.Relation != "providerEndpoint" {
			continue
		}
		bound := false
		for _, binding := range bindings {
			if binding.From.Component == dependency.Component {
				bound = true
				break
			}
		}
		if !bound {
			return fmt.Errorf("providerEndpoint dependency %q requires a binding", dependency.Component)
		}
	}
	return nil
}

func validateEndpoints(endpoints []Endpoint) error {
	known := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Name == "" || endpoint.Scheme == "" {
			return fmt.Errorf("endpoint name and scheme are required")
		}
		if _, exists := known[endpoint.Name]; exists {
			return fmt.Errorf("duplicate endpoint %q", endpoint.Name)
		}
		known[endpoint.Name] = struct{}{}
		if endpoint.Scheme == "unix" {
			if endpoint.Path == "" || endpoint.Port != 0 {
				return fmt.Errorf("unix endpoint %s must set path and omit port", endpoint.Name)
			}
			continue
		}
		if endpoint.Port <= 0 {
			return fmt.Errorf("network endpoint %s must set a positive port", endpoint.Name)
		}
	}
	return nil
}
