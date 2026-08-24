package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// editScenario is the versioned, data-only input to pilot edit automation.
// Values are deliberately limited to non-secret host editing in v1.
type editScenario struct {
	Version int          `json:"version"`
	Title   string       `json:"title"`
	Steps   []editAction `json:"steps"`
}

// editAction describes one semantic operation in an edit scenario.
type editAction struct {
	Action   string `json:"action"`
	Host     string `json:"host,omitempty"`
	Field    string `json:"field,omitempty"`
	Value    string `json:"value,omitempty"`
	ValueEnv string `json:"value_env,omitempty"` // read from the environment at run time instead of Value; mutually exclusive with it
	Role     string `json:"role,omitempty"`
	Key      string `json:"key,omitempty"`  // extra host var / group_vars / vault key name
	File     string `json:"file,omitempty"` // group_vars/vault filename, relative to group_vars/ or .vault/
	// HostVars supplies values for host_vars/<host>.yml keys that
	// enable_role's role newly requires and don't already have a value
	// (inventory.roleContract.HostVarsKeys, e.g. prometheus's
	// prometheus_site_label) — the interactive TUI jumps straight into a
	// text-input prompt for each such key (pushForcedHostVarsPrompt,
	// edit_tui_hostvars.go) instead of leaving it to be noticed later, and
	// enable_role must answer that same prompt rather than error out. Keyed
	// by host_vars key name; disable_role never reads this.
	HostVars map[string]string `json:"host_vars,omitempty"`
	// Label is the role preset name: the *new* label for rename_role_preset,
	// or the label for create_role_preset. Preset is the *existing* preset
	// label being targeted (apply/rename/delete). SourceHost is
	// copy_roles_from_host's source. Roles is create_role_preset's role set.
	Label      string         `json:"label,omitempty"`
	Preset     string         `json:"preset,omitempty"`
	SourceHost string         `json:"source_host,omitempty"`
	Roles      []string       `json:"roles,omitempty"`
	Inventory  string         `json:"inventory,omitempty"`
	Answers    []promptAnswer `json:"answers,omitempty"`
	// User is the roster user name targeted by create_user/set_user_field.
	// A separate field from Host: reusing Host would be semantically wrong
	// (every existing host validator assumes Host names a host).
	User string `json:"user,omitempty"`
	// Name is the roster entity name for the group/hostgroup/HBAC-rule/
	// sudo-command-group/sudo-rule actions (Phase 6 increment 3) — one
	// shared field rather than five near-duplicates, safe because each
	// action name uniquely determines which entity kind Name refers to
	// and no validator ever reads it across two different kinds.
	// Category is create_group's category (team/filesystem/access/role),
	// which also determines the required name prefix. Users/Groups/
	// Hostgroups/Services/CommandGroups are bulk checklist-replace
	// selections (never toggle-one-item — matching the interactive TUI's
	// own "pick the whole set, then Enter" checklists): Users is a
	// group's membership.users; Groups is a group's membership.groups OR
	// an HBAC rule's/sudo rule's subjects.groups; Hostgroups is an HBAC
	// rule's targets.hostgroups; Services is an HBAC rule's services;
	// CommandGroups is a sudo rule's allow.command_groups.
	Name          string   `json:"name,omitempty"`
	Category      string   `json:"category,omitempty"`
	Users         []string `json:"users,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Hostgroups    []string `json:"hostgroups,omitempty"`
	Services      []string `json:"services,omitempty"`
	CommandGroups []string `json:"command_groups,omitempty"`
	// Domain/Realm/Server are create_dns_manifest's freeipa.{domain,realm,server}
	// skeleton fields. Zone is the freeipa-dns manifest's zone name, targeted
	// by create_dns_zone/set_dns_zone_field and by every record action (a
	// record's parent zone). RecordName/RecordType together identify one
	// record within a zone (the schema's own uniqueness key). TargetHost is
	// a record's target.inventory_host; Values is a record's explicit value
	// list — exactly one of TargetHost/Values may be set per record (never
	// both), matching the interactive TUI's own value-source choice.
	Domain     string   `json:"domain,omitempty"`
	Realm      string   `json:"realm,omitempty"`
	Server     string   `json:"server,omitempty"`
	Zone       string   `json:"zone,omitempty"`
	RecordName string   `json:"record_name,omitempty"`
	RecordType string   `json:"record_type,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	Values     []string `json:"values,omitempty"`
	// internal-endpoints.yaml fields (spec.md §39). FQDN is the endpoint's
	// own primary key (spec.md §10.2) — Zone is reused for dns.zone (same
	// semantic as freeipa-dns's own Zone field: a DNS zone name), and Value
	// is reused for set_internal_endpoint_state's new state, matching how
	// DNS's own single-purpose set actions reuse Value for "the new value"
	// rather than adding a dedicated field per action. TargetAddress is
	// route.target's literal-IP alternative to TargetHost (direct mode) —
	// exactly one of the two may be set, never both, matching a DNS
	// record's own TargetHost/Values mutual exclusivity. ProxyHost is
	// route.proxy.inventory_host (reverse_proxy mode); UpstreamHost/
	// UpstreamAddress are route.upstream's inventory_host/address pair
	// (again exactly one).
	FQDN            string `json:"fqdn,omitempty"`
	DNSTTL          string `json:"dns_ttl,omitempty"`
	TargetAddress   string `json:"target_address,omitempty"`
	ProxyHost       string `json:"proxy_host,omitempty"`
	UpstreamScheme  string `json:"upstream_scheme,omitempty"`
	UpstreamHost    string `json:"upstream_host,omitempty"`
	UpstreamAddress string `json:"upstream_address,omitempty"`
	UpstreamPort    string `json:"upstream_port,omitempty"`
	// UpstreamTLSVerify is "true"/"false" (a string, like every other
	// boolean-valued action field in this struct — parsed at Run time),
	// required exactly when UpstreamScheme is "https" (spec.md §12.4.1)
	// and rejected when "http" (spec.md §12.4.4).
	UpstreamTLSVerify string `json:"upstream_tls_verify,omitempty"`
	UpstreamSNI       string `json:"upstream_sni,omitempty"`
	// TLSPort is tls.port (freeipa mode only, optional — 0/absent means
	// "use the scheme default", spec.md §14).
	TLSPort string `json:"tls_port,omitempty"`
	// CertFile/KeyFile/KeyOwner/KeyGroup/KeyMode/ReloadUnit are
	// tls.sink's fields (direct+freeipa only, spec.md §22) —
	// set_internal_endpoint_tls_sink's own parameters.
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	KeyOwner   string `json:"key_owner,omitempty"`
	KeyGroup   string `json:"key_group,omitempty"`
	KeyMode    string `json:"key_mode,omitempty"`
	ReloadUnit string `json:"reload_unit,omitempty"`
	// Monitoring target/scrape-profile fields (spec.md §7-24). Name is
	// reused as the target's or profile's own primary key (same
	// "Name is entity-kind-safe because the action name determines which
	// kind" convention as the roster actions above) — create/set/enable/
	// disable/delete_monitoring_target and create/set/delete_monitoring_profile
	// all key off it. A target label's key/value reuse Key/Value above
	// (same "generic key name"/"generic new value" fields every other
	// single-field set-action already uses) rather than a dedicated pair.
	// Address/Profile/Site are a target's own fields; JobName/Scheme/
	// MetricsPath/ScrapeInterval/ScrapeTimeout/AuthRef/TLSServerName/
	// TLSInsecureSkipVerify are a profile's. TLSInsecureSkipVerify is
	// "true"/"false" like UpstreamTLSVerify above, not a bool — every
	// string-typed boolean action field in this struct is parsed at Run
	// time, never json.Unmarshal'd as bool, so a scenario author can't
	// accidentally omit it and get a silent `false`.
	Address               string `json:"address,omitempty"`
	Profile               string `json:"profile,omitempty"`
	Site                  string `json:"site,omitempty"`
	JobName               string `json:"job_name,omitempty"`
	Scheme                string `json:"scheme,omitempty"`
	MetricsPath           string `json:"metrics_path,omitempty"`
	ScrapeInterval        string `json:"scrape_interval,omitempty"`
	ScrapeTimeout         string `json:"scrape_timeout,omitempty"`
	AuthRef               string `json:"auth_ref,omitempty"`
	TLSServerName         string `json:"tls_server_name,omitempty"`
	TLSInsecureSkipVerify string `json:"tls_insecure_skip_verify,omitempty"`
}

// validateValueOrEnv enforces that exactly one of Value/ValueEnv is set,
// without ever reading the environment itself — validation must be able to
// run (e.g. in CI, linting a scenario file) in an environment where the
// real secret variables are deliberately absent.
func validateValueOrEnv(step editAction, actionName string) error {
	if step.Value != "" && step.ValueEnv != "" {
		return fmt.Errorf("%s accepts either value or value_env, not both", actionName)
	}
	if step.Value == "" && step.ValueEnv == "" {
		return fmt.Errorf("%s requires value or value_env", actionName)
	}
	return nil
}

// validateOptionalValueOrEnv is validateValueOrEnv without the "one of them
// must be set" requirement — for actions where value/value_env only matters
// conditionally at run time (e.g. enable_role's admin password, needed only
// when the role change happens to trigger a secret-bearing bootstrap
// prompt), so a step that never hits that condition may leave both unset.
func validateOptionalValueOrEnv(step editAction, actionName string) error {
	if step.Value != "" && step.ValueEnv != "" {
		return fmt.Errorf("%s accepts either value or value_env, not both", actionName)
	}
	return nil
}

// loadEditScenario reads and validates the JSON envelope. Unknown fields are
// rejected so a typo cannot silently turn into a different operation.
func loadEditScenario(path string) (editScenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return editScenario{}, fmt.Errorf("read edit scenario: %w", err)
	}

	var scenario editScenario
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&scenario); err != nil {
		return editScenario{}, fmt.Errorf("parse edit scenario: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return editScenario{}, fmt.Errorf("parse edit scenario: multiple JSON values")
		}
		return editScenario{}, fmt.Errorf("parse edit scenario: %w", err)
	}
	return scenario, validateEditScenario(scenario)
}

// validateEditScenario enforces the v1 action contract before the TUI starts.
func validateEditScenario(s editScenario) error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported scenario version %d", s.Version)
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("scenario steps must not be empty")
	}
	for i, step := range s.Steps {
		if err := validateEditAction(step); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	return nil
}

func validateEditAction(step editAction) error {
	if _, ok := semanticActionSpecFor(step.Action); !ok {
		return fmt.Errorf("unknown action")
	}
	for _, def := range editActionRegistry() {
		if def.Spec.Name == step.Action {
			return def.Validate(step)
		}
	}
	switch step.Action {
	case "deploy", "reconcile":
		if strings.TrimSpace(step.Inventory) == "" {
			return fmt.Errorf("%s requires inventory", step.Action)
		}
		if len(step.Answers) == 0 {
			return fmt.Errorf("%s requires prompt answers", step.Action)
		}
		return validatePromptAnswers(step.Answers)
	default:
		return fmt.Errorf("action is not executable by the edit workflow")
	}
}

func scenarioUsesValueEnv(steps []editAction) bool {
	for _, s := range steps {
		if s.ValueEnv != "" {
			return true
		}
	}
	return false
}

func hasSecretName(value string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(value))
	for _, marker := range []string{"password", "passwd", "token", "secret", "private_key", "privatekey"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

type automationTraceSink struct {
	path string
	tmp  string
	file *os.File
	enc  *json.Encoder
	err  error
}

func newAutomationTraceSink(path string) (*automationTraceSink, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".pilot-edit-trace-*")
	if err != nil {
		return nil, fmt.Errorf("create automation trace: %w", err)
	}
	return &automationTraceSink{path: path, tmp: file.Name(), file: file, enc: json.NewEncoder(file)}, nil
}

func (s *automationTraceSink) add(event automationTraceEvent) {
	if s == nil || s.enc == nil {
		return
	}
	if err := s.enc.Encode(event); err != nil {
		// The workflow checks sinkErr after each phase; keeping the first error
		// here avoids changing the trace callback's deliberately small type.
		if s.err == nil {
			s.err = err
		}
	}
}

func (s *automationTraceSink) close() error {
	if s == nil {
		return nil
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	return os.Rename(s.tmp, s.path)
}

// openTrecMarkerFD opens the fd trec's `record` announces via TREC_MARKER_FD
// (see trec's AGENTS.md/CLAUDE.md conventions) so automationDriver can
// self-report each step as it happens. Returns nil when the env var is
// absent (not running under trec record) or unparsable.
func openTrecMarkerFD() *os.File {
	fdStr := os.Getenv("TREC_MARKER_FD")
	if fdStr == "" {
		return nil
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), "trec-marker")
}

func runAutomatedEditWorkflow(cmd *cobra.Command, scenario editScenario, presentation bool, tracePath string) error {
	if err := validateEditScenario(scenario); err != nil {
		return err
	}
	var editSteps []editAction
	for _, step := range scenario.Steps {
		if step.Action == "deploy" || step.Action == "reconcile" {
			break
		}
		editSteps = append(editSteps, step)
	}
	hasDeployTail := len(editSteps) < len(scenario.Steps)
	if hasDeployTail && (len(editSteps) == 0 || editSteps[len(editSteps)-1].Action != "save_hosts") {
		return fmt.Errorf("workflow must save hosts before deploy or reconcile")
	}
	if presentation && scenarioUsesValueEnv(scenario.Steps) {
		return fmt.Errorf("--presentation cannot be combined with value_env steps: the resolved secret would be rendered on screen; rerun without --presentation")
	}
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		return err
	}
	if sink != nil {
		defer func() { _ = sink.close() }()
	}
	out := cmd.OutOrStdout()
	marker := openTrecMarkerFD()
	if marker != nil {
		defer marker.Close()
	}
	opts := editAgentSessionOptions{
		Out:          out,
		Presentation: presentation,
		Trace:        func(event automationTraceEvent) { sink.add(event) },
		Marker:       marker,
	}
	if presentation {
		opts.PausePresentation = time.Sleep
	}
	session := newEditAgentSession(editDir, opts)
	if presentation {
		if scenario.Title != "" {
			fmt.Fprintf(out, "═══ %s ═══\n", scenario.Title)
		}
		fmt.Fprintln(out, session.View())
	}
	if err := session.Run(editScenario{Version: 1, Title: scenario.Title, Steps: editSteps}); err != nil {
		return err
	}
	if sink != nil && sink.err != nil {
		return fmt.Errorf("write automation trace: %w", sink.err)
	}
	for _, step := range scenario.Steps[len(editSteps):] {
		if err := runAutomatedDeploymentStep(cmd, step, presentation, out, sink); err != nil {
			return err
		}
		if sink != nil && sink.err != nil {
			return fmt.Errorf("write automation trace: %w", sink.err)
		}
	}
	return nil
}

func runAutomatedDeploymentStep(cmd *cobra.Command, step editAction, presentation bool, out io.Writer, sink *automationTraceSink) error {
	p := &promptAutomation{answers: append([]promptAnswer(nil), step.Answers...), presentation: presentation, out: out}
	oldPrompt := activePromptAutomation
	activePromptAutomation = p
	defer func() { activePromptAutomation = oldPrompt }()
	if step.Inventory != "" {
		if step.Action == "deploy" {
			old := deployInventoryFlag
			deployInventoryFlag = step.Inventory
			defer func() { deployInventoryFlag = old }()
		} else {
			old := reconcileInventoryFlag
			reconcileInventoryFlag = step.Inventory
			defer func() { reconcileInventoryFlag = old }()
		}
	}
	var err error
	if step.Action == "deploy" {
		err = runDeployInteractive(cmd, nil)
	} else {
		err = runReconcileInteractive(cmd)
	}
	for _, event := range p.events {
		sink.add(event)
	}
	if err != nil {
		return err
	}
	if p.err != nil {
		return p.err
	}
	if len(p.answers) != 0 {
		return fmt.Errorf("workflow left %d prompt answers unused", len(p.answers))
	}
	return nil
}

func runStandalonePromptWorkflow(cmd *cobra.Command, action, scenarioPath string, presentation bool, tracePath string) error {
	scenario, err := loadEditScenario(scenarioPath)
	if err != nil {
		return err
	}
	if len(scenario.Steps) != 1 || scenario.Steps[0].Action != action {
		return fmt.Errorf("%s --actions requires exactly one %s action", action, action)
	}
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		return err
	}
	if sink != nil {
		defer func() { _ = sink.close() }()
	}
	err = runAutomatedDeploymentStep(cmd, scenario.Steps[0], presentation, cmd.OutOrStdout(), sink)
	if sink != nil && sink.err != nil {
		return fmt.Errorf("write automation trace: %w", sink.err)
	}
	return err
}
