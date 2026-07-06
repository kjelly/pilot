package cmd

import (
	"strings"
	"testing"
)

// TestBuildGoal_DirectsRunAnsibleFirst pins that the run task's goal
// steers the agent to call run_ansible first instead of exploring the
// filesystem. This is the fix for "the model ran a bunch of tools but
// never ran ansible".
func TestBuildGoal_DirectsRunAnsibleFirst(t *testing.T) {
	goal := buildGoal(playbookTarget{Playbook: "playbooks/test/hello-localhost.yaml"}, "")

	for _, want := range []string{
		"VERY FIRST tool call must be run_ansible",
		"Do NOT explore the filesystem",
		"failed=0",
	} {
		if !strings.Contains(goal, want) {
			t.Errorf("goal missing directive %q\n--- goal ---\n%s", want, goal)
		}
	}
}

// TestBuildGoal_EmptyInventoryTellsModelNotToHunt pins that an empty
// inventory renders an explicit "(none …)" instruction rather than a
// blank line the model fixates on.
func TestBuildGoal_EmptyInventoryTellsModelNotToHunt(t *testing.T) {
	goal := buildGoal(playbookTarget{Playbook: "x.yaml"}, "")
	if !strings.Contains(goal, "do NOT look for or pass an inventory file") {
		t.Errorf("empty inventory should yield a 'do not hunt for inventory' line\n--- goal ---\n%s", goal)
	}

	// A supplied inventory should appear verbatim, not the (none) text.
	goal2 := buildGoal(playbookTarget{Playbook: "x.yaml", Inventory: "/etc/ansible/hosts"}, "")
	if strings.Contains(goal2, "do NOT look for or pass an inventory file") {
		t.Errorf("supplied inventory should not trigger the (none) hint\n--- goal ---\n%s", goal2)
	}
	if !strings.Contains(goal2, "/etc/ansible/hosts") {
		t.Errorf("supplied inventory path should appear in the goal\n--- goal ---\n%s", goal2)
	}
}
