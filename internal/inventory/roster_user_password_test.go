package inventory

import (
	"strings"
	"testing"
)

// userPasswordRoster is grantsRosterBase with alice's password block set to
// passwordYAML (one line per field, indented under `password:`).
func userPasswordRoster(t *testing.T, passwordYAML string) map[string]any {
	t.Helper()
	const alice = "  - name: alice\n    ssh_keys: {authoritative: true, values: []}\n"
	if !strings.Contains(grantsRosterBase, alice) {
		t.Fatal("grantsRosterBase no longer declares alice the way this test expects")
	}
	withPassword := "  - name: alice\n    password:\n" + passwordYAML + "    ssh_keys: {authoritative: true, values: []}\n"
	return mustParseRoster(t, strings.Replace(grantsRosterBase, alice, withPassword, 1))
}

func TestValidateRoster_UserPasswordFlagsAcceptBooleans(t *testing.T) {
	root := userPasswordRoster(t, "      initial: x\n      force_change: true\n      preserve_existing: false\n")
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

// The apply playbook resets an existing password when preserve_existing is
// false; a null or "no" must be rejected before it can be read that way.
func TestValidateRoster_UserPasswordFlagsRejectNonBooleans(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"null preserve_existing", "      initial: x\n      preserve_existing:\n"},
		{"string preserve_existing", "      initial: x\n      preserve_existing: \"no\"\n"},
		{"string force_change", "      initial: x\n      force_change: \"true\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateRosterV3(userPasswordRoster(t, tc.yaml))
			if !contains(ruleNames(v), "user password flag") {
				t.Fatalf("expected a user password flag violation, got: %v", v)
			}
		})
	}
}
