package identityreconcile

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func byName(users []LiveUser, name string) LiveUser {
	for _, u := range users {
		if u.Name == name {
			return u
		}
	}
	return LiveUser{}
}

func groupByName(groups []LiveGroup, name string) LiveGroup {
	for _, g := range groups {
		if g.Name == name {
			return g
		}
	}
	return LiveGroup{}
}

func TestParseCapturedUsers(t *testing.T) {
	users := liveUsers(t, "user-find-states", "user-find-self0", "user-find-reset0", "user-find-nokeys-after")
	if u := byName(users, "p1-off"); !u.Locked || u.Preserved {
		t.Fatalf("p1-off = %+v, want locked, not preserved", u)
	}
	if u := byName(users, "p1-self"); u.LastPwdChange != "20261027070039Z" || u.PwdExpiration != "20270125070039Z" {
		t.Fatalf("p1-self password state = %q %q", u.LastPwdChange, u.PwdExpiration)
	}
	if u := byName(users, "p1-self0"); u.LastPwdChange == "" || u.PwdExpiration != "" {
		t.Fatalf("p1-self0 (maxlife=0 self change) = %q %q, want only a last change", u.LastPwdChange, u.PwdExpiration)
	}
	if u := byName(users, "p1-reset0"); u.LastPwdChange == "" || u.LastPwdChange != u.PwdExpiration {
		t.Fatalf("p1-reset0 (admin reset) = %q %q, want equal", u.LastPwdChange, u.PwdExpiration)
	}
	if u := byName(users, "p1-nopw"); u.LastPwdChange != "" || len(u.Mail) != 2 {
		t.Fatalf("p1-nopw = %+v, want no password and two mails", u)
	}
	if u := byName(users, "p1-keys"); len(u.SSHKeys) != 2 || u.SSHKeysBad != 0 || strings.Contains(u.SSHKeys[0], "p1-key") {
		t.Fatalf("p1-keys keys = %v (bad %d), want two normalized keys without comments", u.SSHKeys, u.SSHKeysBad)
	}
	if u := byName(users, "p1-nokeys"); u.SSHKeys != nil {
		t.Fatalf("p1-nokeys after clearing = %v, want none", u.SSHKeys)
	}
	if u := byName(users, "p1-keys"); !slices.Contains(u.MemberOf, "p1-parent") {
		t.Fatalf("memberof_group is transitive in user_find: %v", u.MemberOf)
	}
}

func TestParseCapturedGroups(t *testing.T) {
	groups := liveGroups(t, "group-find-states", "group-find-nested")
	for name, want := range map[string]string{"p1-team": TypePosix, "p1-parent": TypePosix, "p1-nonposix": TypeNonPosix, "p1-top": TypePosix} {
		if got := groupByName(groups, name).Type; got != want {
			t.Fatalf("%s type = %s, want %s", name, got, want)
		}
	}
	top := groupByName(groups, "p1-top")
	if !slices.Equal(top.MemberGroups, []string{"p1-mid"}) || top.MemberUsers != nil {
		t.Fatalf("p1-top direct members = %v %v; indirect ones must not count", top.MemberUsers, top.MemberGroups)
	}
	parent := groupByName(groups, "p1-parent")
	if !slices.Equal(parent.MemberUsers, []string{"p1-off"}) || !slices.Equal(parent.MemberGroups, []string{"p1-team"}) {
		t.Fatalf("p1-parent direct members = %v %v", parent.MemberUsers, parent.MemberGroups)
	}
}

// Without all: true the answers lack the fields a plan needs; reading
// them must fail rather than look empty.
func TestParseRejectsFindsWithoutAll(t *testing.T) {
	if _, err := ParseUsers(captured(t, "user-find-states-noall")); err == nil {
		t.Fatal("users read without all: true parsed")
	}
	if _, err := ParseGroups(captured(t, "group-find-states-noall")); err == nil {
		t.Fatal("groups read without all: true parsed")
	}
}

func TestGroupTypeNeedsAKnownClassSet(t *testing.T) {
	base := []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"}
	for _, tc := range []struct {
		classes []string
		want    string
	}{
		{base, TypeNonPosix},
		{append(slices.Clone(base), "posixgroup"), TypePosix},
		{append(slices.Clone(base), "posixGroup", "ipaNTGroupAttrs"), TypePosix},
		{append(slices.Clone(base), "ipaexternalgroup"), TypeUnrecognized},
		{append(slices.Clone(base), "posixgroup", "mepmanagedentry"), TypeUnrecognized},
		{base[1:], TypeUnrecognized},
	} {
		if got := groupType(tc.classes); got != tc.want {
			t.Fatalf("groupType(%v) = %s, want %s", tc.classes, got, tc.want)
		}
	}
}

// The marker name must equal the playbook's Jinja hash('sha256') of the
// name as written (captured with ansible-core 2.19.2, 2026-10-30).
func TestHistoryMarkerNameMatchesJinja(t *testing.T) {
	const jinja = "1b4b5bfecb132b85e804e55f5b9013342301c2990183365ff67493cce98afe85" // 'Team-Ops' | hash('sha256')
	if got := HistoryMarkerName("Team-Ops"); got != "pilot-internal-history-g-"+jinja {
		t.Fatalf("HistoryMarkerName = %s", got)
	}
	if HistoryMarkerName("Team-Ops") == HistoryMarkerName("team-ops") {
		t.Fatal("the marker hashes the name as written, not lower-cased")
	}
}

// NormalizeSSHKey must agree with the #138 helper's keyset on the same
// input (AGENTS.md §5.7).
func TestNormalizeSSHKeyMatchesTheHelper(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	helper, err := filepath.Abs(filepath.Join("..", "..", "playbooks", "apply", "files", "freeipa-ssh-key-cache.py"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, u := range captured(t, "user-find-states") {
		list, _ := u["ipasshpubkey"].([]any)
		for _, k := range list {
			keys = append(keys, k.(string))
		}
	}
	if len(keys) == 0 {
		t.Fatal("user-find-states holds no SSH key")
	}
	inputs := append(slices.Clone(keys),
		strings.Fields(keys[0])[0]+" "+strings.Fields(keys[0])[1], // no comment
		"ssh-rsa "+strings.Fields(keys[0])[1],                     // wire type differs
		"ssh-ed25519 not-base64!",
		"rsa-sha2 AAAA",
		"ssh-ed25519",
	)
	for _, in := range inputs {
		script := "import runpy,sys\nns=runpy.run_path(sys.argv[1])\ntry:\n  print(ns['keyset']([sys.argv[2]])[0])\nexcept ValueError:\n  print('INVALID')\n"
		out, err := exec.Command(python, "-I", "-c", script, helper, in).Output()
		if err != nil {
			t.Fatalf("helper on %q: %v", in, err)
		}
		want := strings.TrimSpace(string(out))
		got, gerr := NormalizeSSHKey(in)
		if gerr != nil {
			got = "INVALID"
		}
		if got != want {
			t.Fatalf("NormalizeSSHKey(%q) = %q, helper says %q", in, got, want)
		}
	}
}
