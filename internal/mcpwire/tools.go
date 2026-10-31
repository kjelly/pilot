package mcpwire

import (
	"fmt"
	"sort"
	"strings"
)

// RequiredTools lists tools every remote session of mode must expose.
func RequiredTools(mode string) []string {
	tools := []string{"pilot_edit_inspect", "pilot_edit_plan", "pilot_diagnose_sudo"}
	if mode == ModeEdit {
		tools = append(tools, "pilot_edit_apply")
	}
	return tools
}

// ForbiddenTools lists tools no remote session of mode may expose.
func ForbiddenTools(mode string) []string {
	tools := []string{"pilot_diagnose_run", "pilot_diagnose_snmp_probe"}
	if mode == ModeObserve {
		tools = append(tools, "pilot_edit_apply")
	}
	return tools
}

// ForbiddenToolPrefix matches the repair tool family, never exposed remotely.
const ForbiddenToolPrefix = "pilot_repair_"

// CheckTools reports a missing required tool or a forbidden one.
func CheckTools(mode string, names map[string]bool) error {
	var problems []string
	for _, want := range RequiredTools(mode) {
		if !names[want] {
			problems = append(problems, "missing "+want)
		}
	}
	for _, deny := range ForbiddenTools(mode) {
		if names[deny] {
			problems = append(problems, "unexpected "+deny)
		}
	}
	for name := range names {
		if strings.HasPrefix(name, ForbiddenToolPrefix) {
			problems = append(problems, "unexpected "+name)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%s session tools: %s", mode, strings.Join(problems, ", "))
	}
	return nil
}
