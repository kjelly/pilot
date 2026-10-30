package cmd

import "testing"

func TestValidateLimitFlag(t *testing.T) {
	for _, ok := range []string{"", "host-a", "host-a,host-b", "web:&prod"} {
		if err := validateLimitFlag(ok); err != nil {
			t.Errorf("validateLimitFlag(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"host-a host-b", "host-a\nhost-b", "host-a\t"} {
		if err := validateLimitFlag(bad); err == nil {
			t.Errorf("validateLimitFlag(%q) = nil, want an error", bad)
		}
	}
}

// --force and --preview-only take every prompt's default, so --limit has to be
// the limit prompt's default to reach ansible-playbook at all.
func TestLimitFlagIsTheLimitPromptDefault(t *testing.T) {
	prevPrompt, prevLimit := activePromptAutomation, limitFlag
	t.Cleanup(func() { activePromptAutomation, limitFlag = prevPrompt, prevLimit })
	activePromptAutomation = &promptAutomation{useDefaults: true}

	limitFlag = "host-a,host-b"
	got, err := runTextPrompt(promptLimit, "limit", limitFlag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "host-a,host-b" {
		t.Fatalf("limit prompt = %q, want the --limit value", got)
	}
}
