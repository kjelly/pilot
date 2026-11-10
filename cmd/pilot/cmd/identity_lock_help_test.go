package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The help of the commands that run the identity apply playbook says the same
// thing about the lock precheck, because it is one text (identityLockHelp, and
// identityLockDeployHelp for the two commands whose help is in Chinese), not a
// copy in each file (AGENTS.md §5.7): a copy made when the rule was narrower is
// what let deploy and reconcile keep saying one thing while the other commands
// said another.
func TestLockHelpIsASingleSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
		help string
	}{
		{"pilot access reconcile", accessReconcileCmd, identityLockHelp},
		{"pilot access breakglass activate", accessBreakglassActivateCmd, identityLockHelp},
		{"pilot access breakglass deactivate", accessBreakglassDeactivateCmd, identityLockHelp},
		{"pilot access drift", accessDriftCmd, identityLockHelp},
		{"pilot identity drift", identityDriftCmd, identityLockHelp},
		{"pilot host decommission apply", hostDecommissionApplyCmd, identityLockHelp},
		{"pilot host decommission resume", hostDecommissionResumeCmd, identityLockHelp},
		{"pilot deploy", deployCmd, identityLockDeployHelp},
		{"pilot reconcile", reconcileCmd, identityLockDeployHelp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.cmd.Long, tc.help) {
				t.Fatalf("the help of %s does not carry the lock paragraph:\n%s", tc.name, tc.cmd.Long)
			}
		})
	}

	// No other source file holds a copy: one line of each paragraph, anywhere
	// but identity_lock.go.
	copies := []string{
		"it checks that this server's /etc/ipa lock can be",
		"同一套規則)；取不到(docker 或",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "identity_lock.go" {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, copied := range copies {
			if strings.Contains(string(data), copied) {
				t.Errorf("%s holds a copy of the lock help paragraph (%q): use identityLockHelp or identityLockDeployHelp", name, copied)
			}
		}
	}
}

// What the paragraph claims comes before the check is true of the code, and it
// does not claim that nothing does. A wizard asks its questions first; deploy
// and reconcile regenerate inventory.yml from hosts.yml and upgrade a roster's
// schema before the funnel is entered; decommission confirms the stage first.
// These are the ways "before anything" was not true.
func TestLockHelpDoesNotClaimToComeBeforeEverything(t *testing.T) {
	for _, over := range []string{"before anything", "connects to anything", "在做任何事之前", "做任何事之前"} {
		for name, help := range map[string]string{"identityLockHelp": identityLockHelp, "identityLockDeployHelp": identityLockDeployHelp} {
			if strings.Contains(help, over) {
				t.Errorf("%s claims %q", name, over)
			}
		}
	}
	for _, mention := range []string{"questions of a wizard", "inventory.yml", "schema", "stage confirmation"} {
		if !strings.Contains(identityLockHelp, mention) {
			t.Errorf("identityLockHelp does not say that %q can come before the check", mention)
		}
	}
	for _, mention := range []string{"精靈的問題", "inventory.yml", "schema"} {
		if !strings.Contains(identityLockDeployHelp, mention) {
			t.Errorf("identityLockDeployHelp does not say that %q can come before the check", mention)
		}
	}
}
