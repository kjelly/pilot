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

	verification "github.com/kjelly/pilot/internal/spec"
)

// SchemaVersion is the ComponentContract schema version supported by this loader.
const SchemaVersion = 1

// DefaultDirectory is the repository-relative directory for canonical contracts.
const DefaultDirectory = "contracts"

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
	Diagnostics         Diagnostics  `yaml:"diagnostics"`
	Remediation         Remediation  `yaml:"remediation"`
}

// Remediation is optional component repair metadata consumed by
// pilot_repair_* (Agent Monitoring Phase 3 §4). Absence means no repair
// permission at all for this component. Like Diagnostics, it has no
// "command"/"args"/"playbook"/"extra_vars"/"sudo" field —
// KnownFields(true) decoding rejects any such key outright, so a generic
// executor can never be smuggled in through this metadata.
type Remediation struct {
	Actions []RemediationAction `yaml:"actions"`
}

// RemediationAction is one typed, pre-approved repair action. Phase 3
// only ever accepts Risk "R1" and MaxTargets 1 — R2/R3/R4 and any
// maxTargets != 1 are rejected by the repair planner (internal/repair),
// not just discouraged here, but the contract linter rejects them too
// so a bad contract fails fast at lint time.
type RemediationAction struct {
	ID               string                    `yaml:"id"`
	Risk             string                    `yaml:"risk"` // R1 | R2 | R3 | R4 (R1 autonomous-eligible; R2 always human, canonical_apply only)
	Executor         RemediationActionExecutor `yaml:"executor"`
	MaxTargets       int                       `yaml:"maxTargets"`
	RequiresApproval bool                      `yaml:"requiresApproval"`
	Cooldown         string                    `yaml:"cooldown,omitempty"`
	Verification     RemediationVerification   `yaml:"verification"`
	Autonomy         RemediationAutonomy       `yaml:"autonomy,omitempty"`
	Preflight        RemediationPreflight      `yaml:"preflight,omitempty"`
}

// RemediationPreflight is Agent Monitoring Phase 5's canonical_apply-only
// gate (design doc §5): both flags exist so the linter can enforce that
// an R2 action explicitly declares the evidence it depends on, rather
// than silently assuming it. internal/repair's preflight always performs
// the dependency-health check regardless of this flag's value (§10:
// "resolve required dependencies... validate dependencies" is
// unconditional) — RequireDependencyHealth exists for declarative
// clarity in the contract, not to make the check optional.
type RemediationPreflight struct {
	RequireIdempotencyEvidence bool `yaml:"requireIdempotencyEvidence"`
	RequireDependencyHealth    bool `yaml:"requireDependencyHealth"`
}

// RemediationAutonomy is Agent Monitoring Phase 4's per-environment
// autonomy opt-in (design doc §4) — a missing block, or any field left
// empty, means human approval is required for that environment. This is
// a per-action, per-environment ALLOWLIST: the policy engine
// (internal/policy) additionally requires the environment's own default
// posture (allow_r1) and all 15 mandatory guards before this opt-in ever
// results in autonomous execution.
type RemediationAutonomy struct {
	Sandbox string `yaml:"sandbox,omitempty"` // "allowed" | "human" | "" (missing = human)
	Staging string `yaml:"staging,omitempty"`
	Prod    string `yaml:"prod,omitempty"`
}

// RemediationActionExecutor names a fixed, typed operation — never a
// caller- or Agent-suppliable command. Target is always resolved from
// the contract at plan time, never from Agent/MCP-caller input.
type RemediationActionExecutor struct {
	Kind   string `yaml:"kind"` // docker_restart | systemd_restart | systemd_reload
	Target string `yaml:"target"`
}

// RemediationVerification names the spec a repair action's success is
// judged against — never process exit code alone (Agent Monitoring
// Phase 3 §9).
type RemediationVerification struct {
	Spec string `yaml:"spec"`
}

// Diagnostics is optional component-diagnostic metadata consumed by
// pilot_diagnose_component (Agent Monitoring Phase 2 §4) instead of a
// forever-growing per-component switch statement in Go. It deliberately
// has no "command"/"shell" field — KnownFields(true) decoding rejects
// any such key outright, so a generic executor cannot be smuggled in
// through this metadata even by a future careless edit.
type Diagnostics struct {
	Runtime    DiagnosticsRuntime   `yaml:"runtime"`
	Readiness  DiagnosticsReadiness `yaml:"readiness"`
	Logs       DiagnosticsLogs      `yaml:"logs"`
	VerifySpec string               `yaml:"verifySpec"`
}

// DiagnosticsRuntime names how this component's process is supervised.
// Kind "" means no diagnostics block was configured at all — distinct
// from Kind "none", which is an explicit "this component has no
// supervised runtime process to check."
type DiagnosticsRuntime struct {
	Kind string `yaml:"kind"` // docker | systemd | none
	Name string `yaml:"name"`
}

// DiagnosticsReadiness names an HTTP readiness probe against one of this
// contract's own Endpoints entries — never an arbitrary caller-supplied
// host:port.
type DiagnosticsReadiness struct {
	Endpoint string `yaml:"endpoint"`
	Path     string `yaml:"path"`
}

// DiagnosticsLogs names where component_health's bounded recent-error
// summary comes from.
type DiagnosticsLogs struct {
	Source   string `yaml:"source"` // docker | systemd
	Lookback string `yaml:"lookback"`
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
	Component string   `yaml:"component"`
	Required  bool     `yaml:"required"`
	Relation  string   `yaml:"relation"`
	Reason    string   `yaml:"reason"`
	Endpoints []string `yaml:"endpoints"`
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
	Name        string       `yaml:"name"`
	Scheme      string       `yaml:"scheme"`
	Port        int          `yaml:"port"`
	Path        string       `yaml:"path"`
	AutoPublish *AutoPublish `yaml:"autoPublish"`
}

// AutoPublish declares whether an http/https endpoint is a candidate for the
// internal-endpoint auto-provision suggester (`pilot internal-endpoint
// suggest`, and the edit-TUI's endpoint menu). Eligible defaults to false:
// publishing a service through the shared reverse-proxy is an explicit,
// per-endpoint opt-in, never inferred from scheme=http alone. Endpoints that
// are deliberately excluded (freeipa-server's own https, the metrics-stack
// operational surfaces) still declare this block with eligible: false and a
// Reason, so the exclusion reads as a decision, not an oversight.
type AutoPublish struct {
	Eligible  bool   `yaml:"eligible"`
	Subdomain string `yaml:"subdomain"`
	Reason    string `yaml:"reason"`
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

// LoadDefaultCatalog loads the repository's canonical contracts directory.
func (l Loader) LoadDefaultCatalog() (Catalog, error) {
	return l.LoadCatalog(DefaultDirectory)
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

// Components returns every contract in the stable order loaded by the catalog.
func (c Catalog) Components() []Contract {
	return append([]Contract(nil), c.contracts...)
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
		if !hasV2FrontMatter(data) {
			return fmt.Errorf("verification.autoDeploy requires Spec v2: %s", entry.Path)
		}
		parsed, err := verification.Parse(path)
		if err != nil {
			return fmt.Errorf("autoDeploy spec %s: %w", entry.Path, err)
		}
		if parsed.SchemaVersion != 2 {
			return fmt.Errorf("verification.autoDeploy requires Spec v2: %s", entry.Path)
		}
		if len(parsed.Rows) == 0 {
			return fmt.Errorf("verification.autoDeploy spec %s has no checks", entry.Path)
		}
	}
	return nil
}

func hasV2FrontMatter(data []byte) bool {
	return bytes.HasPrefix(data, []byte("---\n")) || bytes.HasPrefix(data, []byte("---\r\n"))
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
	if err := validateDiagnostics(contract.Diagnostics, contract.Endpoints, contract.Specs); err != nil {
		return err
	}
	if err := validateRemediation(contract.Remediation, contract.Specs, contract.Playbooks); err != nil {
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
		if len(dependency.Endpoints) > 0 {
			if dependency.Relation != "providerEndpoint" {
				return fmt.Errorf("dependency %q endpoints filter requires providerEndpoint relation", dependency.Component)
			}
			seen := make(map[string]struct{}, len(dependency.Endpoints))
			for _, name := range dependency.Endpoints {
				if name == "" {
					return fmt.Errorf("dependency %q endpoints entry cannot be empty", dependency.Component)
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("dependency %q duplicate endpoints entry %q", dependency.Component, name)
				}
				seen[name] = struct{}{}
			}
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
		if endpoint.AutoPublish != nil && endpoint.AutoPublish.Eligible && endpoint.Scheme != "http" && endpoint.Scheme != "https" {
			return fmt.Errorf("endpoint %s: autoPublish.eligible requires scheme http or https, got %q", endpoint.Name, endpoint.Scheme)
		}
	}
	return nil
}

// validateDiagnostics enforces Agent Monitoring Phase 2's linter checks
// (design doc §9 Task 3): runtime kind enum, runtime target non-empty
// and no wildcard, endpoint reference exists, verification spec belongs
// to this component. Runtime.Kind == "" means no diagnostics block was
// configured — entirely optional, skip all checks.
func validateDiagnostics(d Diagnostics, endpoints []Endpoint, specs []Spec) error {
	if d.Runtime.Kind == "" {
		return nil
	}
	switch d.Runtime.Kind {
	case "docker", "systemd", "none":
	default:
		return fmt.Errorf("diagnostics.runtime.kind must be docker, systemd, or none, got %q", d.Runtime.Kind)
	}
	if d.Runtime.Kind != "none" {
		if strings.TrimSpace(d.Runtime.Name) == "" {
			return fmt.Errorf("diagnostics.runtime.name is required when kind is %q", d.Runtime.Kind)
		}
		if strings.ContainsAny(d.Runtime.Name, "*?") {
			return fmt.Errorf("diagnostics.runtime.name %q must not be a wildcard pattern", d.Runtime.Name)
		}
	}
	if d.Readiness.Endpoint != "" {
		found := false
		for _, e := range endpoints {
			if e.Name == d.Readiness.Endpoint {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("diagnostics.readiness.endpoint %q does not match any endpoints[].name", d.Readiness.Endpoint)
		}
	}
	if d.VerifySpec != "" {
		found := false
		for _, s := range specs {
			if s.Path == d.VerifySpec {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("diagnostics.verifySpec %q does not match any of this component's specs[].path", d.VerifySpec)
		}
	}
	return nil
}

// validRemediationExecutorKinds is Phase 3's first slice (design doc §4)
// plus Phase 5's "canonical_apply" (design doc §5) — deliberately
// narrow; widen only with actual reviewed evidence per kind, never
// speculatively.
var validRemediationExecutorKinds = map[string]bool{
	"docker_restart":  true,
	"systemd_restart": true,
	"systemd_reload":  true,
	"canonical_apply": true,
}

// validateRemediation enforces Agent Monitoring Phase 3/5's contract/
// linter checks (design doc §12 / Phase 5 §16): no remediation block ->
// zero actions (nothing to validate, handled by the empty-slice range
// below); duplicate IDs rejected; invalid risk/executor enum rejected;
// wildcard/empty executor target rejected (except "canonical_apply",
// which has no fixed target — the real target is the host, resolved at
// plan time, and the playbook comes from playbooks.apply, never
// executor.target); maxTargets != 1 rejected (only ever executes
// exactly one host); verification spec must exist/belong to this
// component. "canonical_apply" is additionally restricted to risk R2
// (Phase 5 §5: "canonical_apply contains no caller-configurable
// playbook field"), requires playbooks.apply to actually exist (nothing
// to reapply otherwise), and requires requiresApproval — R2 is never
// autonomous in this phase, so a contract that forgets this flag still
// fails at lint time rather than only being caught by internal/policy's
// runtime guard. R3/R4 actions may be DECLARED (a future phase may read
// them) but no planner in this codebase ever plans/executes anything
// but R1/R2 — that check lives in internal/repair, not here, since
// "declared but not yet executable" is a valid contract state.
func validateRemediation(r Remediation, specs []Spec, playbooks Playbooks) error {
	seen := map[string]bool{}
	for _, a := range r.Actions {
		if strings.TrimSpace(a.ID) == "" {
			return fmt.Errorf("remediation action id is required")
		}
		if seen[a.ID] {
			return fmt.Errorf("duplicate remediation action id %q", a.ID)
		}
		seen[a.ID] = true

		switch a.Risk {
		case "R1", "R2", "R3", "R4":
		default:
			return fmt.Errorf("remediation action %q: risk must be R1, R2, R3, or R4, got %q", a.ID, a.Risk)
		}
		if !validRemediationExecutorKinds[a.Executor.Kind] {
			return fmt.Errorf("remediation action %q: executor.kind must be docker_restart, systemd_restart, systemd_reload, or canonical_apply, got %q", a.ID, a.Executor.Kind)
		}
		if a.Executor.Kind == "canonical_apply" {
			if a.Risk != "R2" {
				return fmt.Errorf("remediation action %q: executor.kind canonical_apply is only valid for risk R2, got %q", a.ID, a.Risk)
			}
			if !a.RequiresApproval {
				return fmt.Errorf("remediation action %q: requiresApproval must be true for canonical_apply — R2 is never autonomous", a.ID)
			}
			if strings.TrimSpace(playbooks.Apply) == "" {
				return fmt.Errorf("remediation action %q: canonical_apply requires this component's own playbooks.apply to be set", a.ID)
			}
		} else if strings.TrimSpace(a.Executor.Target) == "" {
			return fmt.Errorf("remediation action %q: executor.target is required", a.ID)
		} else if strings.ContainsAny(a.Executor.Target, "*?") {
			return fmt.Errorf("remediation action %q: executor.target %q must not be a wildcard pattern", a.ID, a.Executor.Target)
		}
		if a.MaxTargets != 1 {
			return fmt.Errorf("remediation action %q: maxTargets must be exactly 1, got %d", a.ID, a.MaxTargets)
		}
		if strings.TrimSpace(a.Verification.Spec) == "" {
			return fmt.Errorf("remediation action %q: verification.spec is required", a.ID)
		}
		found := false
		for _, s := range specs {
			if s.Path == a.Verification.Spec {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("remediation action %q: verification.spec %q does not match any of this component's specs[].path", a.ID, a.Verification.Spec)
		}
		for env, v := range map[string]string{"sandbox": a.Autonomy.Sandbox, "staging": a.Autonomy.Staging, "prod": a.Autonomy.Prod} {
			switch v {
			case "", "allowed", "human":
			default:
				return fmt.Errorf("remediation action %q: autonomy.%s must be \"allowed\" or \"human\", got %q", a.ID, env, v)
			}
		}
	}
	return nil
}
