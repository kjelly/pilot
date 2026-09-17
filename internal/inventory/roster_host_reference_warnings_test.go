package inventory

import (
	"strings"
	"testing"
)

func TestRosterDanglingHostReferenceWarnings_FlagsEveryReferenceKind(t *testing.T) {
	root := mustParseRoster(t, `
hosts:
  - {name: present.ipa.pilot.internal, state: present, ip_address: 10.0.0.1}
  - {name: decommissioned.ipa.pilot.internal, state: absent, ip_address: 10.0.0.2}
hostgroups:
  - name: hg1
    membership: {hosts: [present.ipa.pilot.internal, missing-hg.ipa.pilot.internal]}
netgroups:
  - name: ng1
    membership: {hosts: [missing-ng.ipa.pilot.internal]}
hbac:
  rules:
    - name: hbac1
      targets: {hosts: [decommissioned.ipa.pilot.internal]}
sudo:
  rules:
    - name: sudo1
      targets: {hosts: [missing-sudo.ipa.pilot.internal]}
`)
	warnings := RosterDanglingHostReferenceWarnings(root)
	if len(warnings) != 4 {
		t.Fatalf("RosterDanglingHostReferenceWarnings() = %+v, want 4 entries", warnings)
	}
	for _, w := range warnings {
		if w.Rule != "dangling host reference" {
			t.Fatalf("warning.Rule = %q, want \"dangling host reference\"", w.Rule)
		}
	}
	joined := ""
	for _, w := range warnings {
		joined += w.Detail + "\n"
	}
	for _, want := range []string{"missing-hg.ipa.pilot.internal", "missing-ng.ipa.pilot.internal", "decommissioned.ipa.pilot.internal", "missing-sudo.ipa.pilot.internal"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings = %q, want a mention of %q", joined, want)
		}
	}
	if strings.Contains(joined, `"present.ipa.pilot.internal"`) {
		t.Fatalf("warnings = %q, present host must not be flagged", joined)
	}
}

func TestRosterDanglingHostReferenceWarnings_NoneWhenEverythingResolves(t *testing.T) {
	root := mustParseRoster(t, `
hosts:
  - {name: web1.ipa.pilot.internal, state: present, ip_address: 10.0.0.1}
hostgroups:
  - name: hg1
    membership: {hosts: [web1.ipa.pilot.internal]}
hbac:
  rules:
    - name: hbac1
      targets: {hosts: [web1.ipa.pilot.internal]}
`)
	if warnings := RosterDanglingHostReferenceWarnings(root); len(warnings) != 0 {
		t.Fatalf("RosterDanglingHostReferenceWarnings() = %+v, want none", warnings)
	}
}

func TestRosterDanglingHostReferenceWarnings_AllHostsCategorySkipsExplicitList(t *testing.T) {
	root := mustParseRoster(t, `
hbac:
  rules:
    - name: hbac-all
      targets: {hostcategory: all}
`)
	if warnings := RosterDanglingHostReferenceWarnings(root); len(warnings) != 0 {
		t.Fatalf("RosterDanglingHostReferenceWarnings() = %+v, want none (hostcategory: all has no explicit hosts list)", warnings)
	}
}
