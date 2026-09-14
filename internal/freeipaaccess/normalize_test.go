package freeipaaccess

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) rpcEnvelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	env, err := decodeEnvelope(data)
	if err != nil {
		if _, ok := errors.AsType[*RPCError](err); !ok {
			t.Fatalf("decode fixture %s: %v", name, err)
		}
	}
	return env
}

func TestParsePing(t *testing.T) {
	env := loadFixture(t, "ping.json")
	r, err := parsePing(env)
	if err != nil {
		t.Fatalf("parsePing: %v", err)
	}
	if r.ServerVersion == "" {
		t.Fatalf("expected non-empty server version")
	}
}

func TestParseUser(t *testing.T) {
	env := loadFixture(t, "user_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	u := parseUser(m)
	if u.Username != "alice" {
		t.Fatalf("Username = %q, want alice", u.Username)
	}
	if !u.Enabled {
		t.Fatalf("expected alice to be Enabled (nsaccountlock=false)")
	}
	wantGroups := []string{"ipausers", "gpu-users"}
	if !stringSliceEqualUnordered(u.DirectGroups, wantGroups) {
		t.Fatalf("DirectGroups = %v, want %v", u.DirectGroups, wantGroups)
	}
}

func TestParseGroup(t *testing.T) {
	env := loadFixture(t, "group_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	g := parseGroup(m)
	if g.Name != "gpu-users" {
		t.Fatalf("Name = %q, want gpu-users", g.Name)
	}
	if !stringSliceEqualUnordered(g.MemberUsers, []string{"alice"}) {
		t.Fatalf("MemberUsers = %v, want [alice]", g.MemberUsers)
	}
	if len(g.MemberGroups) != 0 {
		t.Fatalf("MemberGroups = %v, want empty (no nested group in fixture)", g.MemberGroups)
	}
}

func TestParseHost(t *testing.T) {
	env := loadFixture(t, "host_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	h := parseHost(m)
	if h.FQDN != "gpu-a.ipa.pilot.internal" {
		t.Fatalf("FQDN = %q", h.FQDN)
	}
}

func TestParseHostgroup(t *testing.T) {
	env := loadFixture(t, "hostgroup_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	hg := parseHostgroup(m)
	if hg.Name != "pilot-target-gpu" {
		t.Fatalf("Name = %q", hg.Name)
	}
	want := []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal"}
	if !stringSliceEqualUnordered(hg.MemberHosts, want) {
		t.Fatalf("MemberHosts = %v, want %v", hg.MemberHosts, want)
	}
	if len(hg.MemberHostgroups) != 0 {
		t.Fatalf("MemberHostgroups = %v, want empty (no nested hostgroup in fixture)", hg.MemberHostgroups)
	}
}

func TestParseHBACRuleShow(t *testing.T) {
	env := loadFixture(t, "hbacrule_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	r := parseHBACRule(m)
	if r.Name != "pilot-grant-login-gpu-test" {
		t.Fatalf("Name = %q", r.Name)
	}
	if !r.Enabled {
		t.Fatalf("expected rule enabled")
	}
	if r.UserCategoryAll || r.HostCategoryAll || r.ServiceCategoryAll {
		t.Fatalf("expected no category-all flags set on a specific rule")
	}
	if !stringSliceEqualUnordered(r.Groups, []string{"gpu-users"}) {
		t.Fatalf("Groups = %v", r.Groups)
	}
	if !stringSliceEqualUnordered(r.Hostgroups, []string{"pilot-target-gpu"}) {
		t.Fatalf("Hostgroups = %v", r.Hostgroups)
	}
	if !stringSliceEqualUnordered(r.Services, []string{"sshd"}) {
		t.Fatalf("Services = %v", r.Services)
	}
}

// TestParseHBACRuleFind exercises category-all and disabled-rule parsing
// against FreeIPA's own built-in rules (allow_all, allow_systemd-user),
// which this environment's fixtures happen to carry for free.
func TestParseHBACRuleFind(t *testing.T) {
	env := loadFixture(t, "hbacrule_find.json")
	rows, err := decodeFind(env)
	if err != nil {
		t.Fatalf("decodeFind: %v", err)
	}
	byName := map[string]HBACRule{}
	for _, row := range rows {
		r := parseHBACRule(row)
		byName[r.Name] = r
	}
	allowAll, ok := byName["allow_all"]
	if !ok {
		t.Fatalf("expected allow_all in fixture")
	}
	if allowAll.Enabled {
		t.Fatalf("allow_all was disabled during fixture capture; Enabled must be false")
	}
	if !allowAll.UserCategoryAll || !allowAll.HostCategoryAll || !allowAll.ServiceCategoryAll {
		t.Fatalf("allow_all should have all three category-all flags set: %+v", allowAll)
	}
	systemdUser, ok := byName["allow_systemd-user"]
	if !ok {
		t.Fatalf("expected allow_systemd-user in fixture")
	}
	if !systemdUser.Enabled {
		t.Fatalf("allow_systemd-user should be enabled")
	}
	if systemdUser.ServiceCategoryAll {
		t.Fatalf("allow_systemd-user has a specific service, not servicecategory=all")
	}
	if !stringSliceEqualUnordered(systemdUser.Services, []string{"systemd-user"}) {
		t.Fatalf("Services = %v", systemdUser.Services)
	}
	ours, ok := byName["pilot-grant-login-gpu-test"]
	if !ok || !ours.Enabled {
		t.Fatalf("expected pilot-grant-login-gpu-test enabled in find results")
	}
}

func TestParseHBACServiceGroup(t *testing.T) {
	env := loadFixture(t, "hbacsvcgroup_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	g := parseHBACServiceGroup(m)
	if g.Name != "test-svc-group" {
		t.Fatalf("Name = %q", g.Name)
	}
	if !stringSliceEqualUnordered(g.Services, []string{"sshd"}) {
		t.Fatalf("Services = %v", g.Services)
	}
}

func TestParseSudoRuleShow(t *testing.T) {
	env := loadFixture(t, "sudorule_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	r, err := parseSudoRule(m)
	if err != nil {
		t.Fatalf("parseSudoRule: %v", err)
	}
	if r.Name != "pilot-grant-sudo-gpu-test" {
		t.Fatalf("Name = %q", r.Name)
	}
	if !r.Enabled {
		t.Fatalf("expected rule enabled")
	}
	if !stringSliceEqualUnordered(r.AllowCommands, []string{"/usr/bin/systemctl status nginx"}) {
		t.Fatalf("AllowCommands = %v", r.AllowCommands)
	}
	if !stringSliceEqualUnordered(r.AllowCommandGroups, []string{"test-sudocmdgroup"}) {
		t.Fatalf("AllowCommandGroups = %v", r.AllowCommandGroups)
	}
	if !stringSliceEqualUnordered(r.DenyCommands, []string{"/usr/bin/reboot"}) {
		t.Fatalf("DenyCommands = %v", r.DenyCommands)
	}
	if r.NotBefore == nil || r.NotAfter == nil {
		t.Fatalf("expected NotBefore/NotAfter to be set")
	}
	wantBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !r.NotBefore.Equal(wantBefore) {
		t.Fatalf("NotBefore = %v, want %v", r.NotBefore, wantBefore)
	}
	if !r.NotAfter.Equal(wantAfter) {
		t.Fatalf("NotAfter = %v, want %v", r.NotAfter, wantAfter)
	}
}

func TestParseSudoRuleFind(t *testing.T) {
	env := loadFixture(t, "sudorule_find.json")
	rows, err := decodeFind(env)
	if err != nil {
		t.Fatalf("decodeFind: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("expected at least one sudo rule in find results")
	}
	for _, row := range rows {
		if _, err := parseSudoRule(row); err != nil {
			t.Fatalf("parseSudoRule: %v", err)
		}
	}
}

func TestParseSudoCommand(t *testing.T) {
	env := loadFixture(t, "sudocmd_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	c := parseSudoCommand(m)
	if c.Command != "/usr/bin/systemctl status nginx" {
		t.Fatalf("Command = %q", c.Command)
	}
}

func TestParseSudoCommandGroup(t *testing.T) {
	env := loadFixture(t, "sudocmdgroup_show.json")
	m, err := decodeShow(env)
	if err != nil {
		t.Fatalf("decodeShow: %v", err)
	}
	g := parseSudoCommandGroup(m)
	if g.Name != "test-sudocmdgroup" {
		t.Fatalf("Name = %q", g.Name)
	}
	if !stringSliceEqualUnordered(g.Commands, []string{"/usr/bin/systemctl status nginx"}) {
		t.Fatalf("Commands = %v", g.Commands)
	}
}

func TestParseHBACTestAllowDeny(t *testing.T) {
	allow, err := parseHBACTest(loadFixture(t, "hbactest_allow.json"))
	if err != nil {
		t.Fatalf("parseHBACTest allow: %v", err)
	}
	if !allow.Access {
		t.Fatalf("expected hbactest_allow.json to grant access")
	}
	if !stringSliceEqualUnordered(allow.Matched, []string{"pilot-grant-login-gpu-test"}) {
		t.Fatalf("Matched = %v", allow.Matched)
	}

	deny, err := parseHBACTest(loadFixture(t, "hbactest_deny.json"))
	if err != nil {
		t.Fatalf("parseHBACTest deny: %v", err)
	}
	if deny.Access {
		t.Fatalf("expected hbactest_deny.json to deny access")
	}
}

func TestDecodeEnvelopeRPCError(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rpc_error.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	_, err = decodeEnvelope(data)
	if err == nil {
		t.Fatalf("expected an error")
	}
	rpcErr, ok := errors.AsType[*RPCError](err)
	if !ok {
		t.Fatalf("expected *RPCError, got %T: %v", err, err)
	}
	if rpcErr.Name != "NotFound" {
		t.Fatalf("Name = %q, want NotFound", rpcErr.Name)
	}
	if rpcErr.Code != 4001 {
		t.Fatalf("Code = %d, want 4001", rpcErr.Code)
	}
}

func stringSliceEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, s := range a {
		count[s]++
	}
	for _, s := range b {
		count[s]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}
