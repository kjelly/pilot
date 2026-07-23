package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	Action    string         `json:"action"`
	Host      string         `json:"host,omitempty"`
	Field     string         `json:"field,omitempty"`
	Value     string         `json:"value,omitempty"`
	Role      string         `json:"role,omitempty"`
	Label     string         `json:"label,omitempty"`
	Inventory string         `json:"inventory,omitempty"`
	Answers   []promptAnswer `json:"answers,omitempty"`
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
	switch step.Action {
	case "create_host":
		if strings.TrimSpace(step.Host) == "" {
			return fmt.Errorf("create_host requires host")
		}
		if hasSecretName(step.Host) {
			return fmt.Errorf("secret-like host names are not allowed")
		}
		return nil
	case "set_host_field":
		if strings.TrimSpace(step.Host) == "" {
			return fmt.Errorf("set_host_field requires host")
		}
		if strings.TrimSpace(step.Field) == "" {
			return fmt.Errorf("set_host_field requires field")
		}
		if hasSecretName(step.Field) {
			return fmt.Errorf("secret values are not accepted")
		}
		spec, _ := semanticActionSpecFor(step.Action)
		allowed := false
		for _, field := range spec.Values["field"] {
			if step.Field == field {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("unsupported host field")
		}
		return nil
	case "enable_role":
		if strings.TrimSpace(step.Host) == "" {
			return fmt.Errorf("enable_role requires host")
		}
		if strings.TrimSpace(step.Role) == "" {
			return fmt.Errorf("enable_role requires role")
		}
		if hasSecretName(step.Role) {
			return fmt.Errorf("secret-like role names are not allowed")
		}
		return nil
	case "save_hosts":
		if step.Host != "" || step.Field != "" || step.Value != "" || step.Role != "" || step.Label != "" || step.Inventory != "" || len(step.Answers) > 0 {
			return fmt.Errorf("save_hosts does not accept parameters")
		}
		return nil
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
	if len(editSteps) == 0 || editSteps[len(editSteps)-1].Action != "save_hosts" {
		return fmt.Errorf("workflow must save hosts before deploy or reconcile")
	}
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		return err
	}
	if sink != nil {
		defer func() { _ = sink.close() }()
	}
	out := cmd.OutOrStdout()
	r := newEditRouterModel(editDir)
	f := func(event automationTraceEvent) { sink.add(event) }
	d := automationDriver{trace: f, presentation: presentation, out: out}
	if presentation {
		if scenario.Title != "" {
			fmt.Fprintf(out, "═══ %s ═══\n", scenario.Title)
		}
		fmt.Fprintln(out, r.View())
	}
	if err := d.run(&r, editScenario{Version: 1, Title: scenario.Title, Steps: editSteps}); err != nil {
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
