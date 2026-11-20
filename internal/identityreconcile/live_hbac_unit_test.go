package identityreconcile

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// The logic of the HBAC live driver that does not need the lab, on what the lab said: the lines are the commands of
// FreeIPA 4.13.4's own log (testdata/server-log-hbac-commands.txt, from the P3-5 lab run: reads, a direct
// hbacrule_disable, and batched writes, each batched write logged twice).

func TestCountHBACWritesCountsEachWriteOnce(t *testing.T) {
	raw, err := os.ReadFile("testdata/server-log-hbac-commands.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hbacrule_disable", "hbacrule_remove_host", "hbacrule_mod", "hbacrule_add_user", "hbacrule_enable", "hbacrule_del", "hbacrule_mod", "hbacrule_add_host"}
	if got := countHBACWrites(string(raw)); !slices.Equal(got, want) {
		t.Errorf("writes %v, want %v", got, want)
	}
}

// The case that fires: a log of reads only has no write, and the finds and shows are not mistaken for one.
func TestCountHBACWritesIgnoresReads(t *testing.T) {
	var reads []string
	for _, line := range strings.Split(strings.TrimSpace(mustRead(t, "testdata/server-log-hbac-commands.txt")), "\n") {
		if strings.Contains(line, "hbacrule_find(") || strings.Contains(line, "hbacsvc_find(") || strings.Contains(line, "hbacrule_show(") {
			reads = append(reads, line)
		}
	}
	if len(reads) == 0 {
		t.Fatal("the fixture has no read")
	}
	if got := countHBACWrites(strings.Join(reads, "\n")); len(got) != 0 {
		t.Errorf("reads counted as writes: %v", got)
	}
	// A member command is not its rule's own add, and an add is not the lockdown's disable.
	if got := countHBACWrites("ipa: INFO: x: hbacrule_add_host('r', hostgroup=('g',)): SUCCESS"); !slices.Equal(got, []string{"hbacrule_add_host"}) {
		t.Errorf("a member add is %v", got)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// parseLiveRules reads the CLI's raw output of the lab (testdata/hbacrule-find-all-raw.txt, FreeIPA 4.13.4): the
// built-in rules and one with each kind of member, disabled, and no category.
func TestParseLiveRulesReadsTheCLIsOutput(t *testing.T) {
	rules := parseLiveRules(mustRead(t, "testdata/hbacrule-find-all-raw.txt"))
	if len(rules) != 4 {
		t.Fatalf("%d rules, want 4: %v", len(rules), rules)
	}
	if r := rules["allow_all"]; r.Enabled || r.HostCat != "all" || r.UserCat != "all" || r.ServiceCat != "all" {
		t.Errorf("allow_all is %+v, want disabled with all three categories", r)
	}
	if r := rules["p26-admin"]; !r.Enabled || r.HostCat != "all" || !slices.Equal(r.Users, []string{"admin"}) || !slices.Equal(r.Services, []string{"sshd"}) {
		t.Errorf("p26-admin is %+v", r)
	}
	r := rules["p26-ssh"]
	if r.Enabled || r.HostCat != "" || !slices.Equal(r.Hostgroups, []string{"p26-targets"}) || !slices.Equal(r.Hosts, []string{"h3a-cli.ipa.pilot.internal"}) ||
		!slices.Equal(r.Groups, []string{"team-p26"}) || !slices.Equal(r.Services, []string{"sshd", "sudo"}) || len(r.Users) != 7 || r.Users[0] != "p26-adm" {
		t.Errorf("p26-ssh is %+v", r)
	}
}

// The case that fires: a rule on the server that differs from the roster is not taken for it, and an absent one is.
func TestExpectedRulesAgainstTheServersRules(t *testing.T) {
	live := parseLiveRules(mustRead(t, "testdata/hbacrule-find-all-raw.txt"))
	roster := rosterDoc{"hbac": map[string]any{"rules": []map[string]any{
		{"name": "P26-Admin", "enabled": true, "subjects": map[string]any{"users": []string{"admin"}}, "targets": map[string]any{"hostcat": "all"}, "services": []string{"sshd"}},
		{"name": "p26-gone", "state": "absent", "subjects": map[string]any{"users": []string{"admin"}}, "targets": map[string]any{"hostcat": "all"}, "services": []string{"sshd"}},
	}}}
	want, absent := expectedRules(roster)
	got := live["p26-admin"]
	if w := want["p26-admin"]; got.Enabled != w.Enabled || got.HostCat != w.HostCat || !slices.Equal(got.Users, w.Users) || !slices.Equal(got.Services, w.Services) {
		t.Errorf("the roster's rule (as spelled P26-Admin) is %+v and the server's %+v", w, got)
	}
	if !slices.Equal(absent, []string{"p26-gone"}) {
		t.Errorf("absent %v", absent)
	}
	if _, ok := live["p26-gone"]; ok {
		t.Error("the server has the rule the roster marks absent")
	}
	// The roster's rule with one more service than the server's is different.
	wide := roster["hbac"].(map[string]any)["rules"].([]map[string]any)[0]
	wide["services"] = []string{"sshd", "su"}
	want2, _ := expectedRules(roster)
	if slices.Equal(want2["p26-admin"].Services, live["p26-admin"].Services) {
		t.Error("a rule with another service reads as the server's")
	}
}
