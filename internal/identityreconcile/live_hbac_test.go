package identityreconcile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestLiveHBACDriver is the Phase 3a part of the Go reconcile test driver (spec 2026-11-19 phase 3a §8.2, P3-6): the
// arms of the mixed run's HBAC stage (`pilot reconcile --engine golang --scope full`) against a disposable FreeIPA
// server and an enrolled client, driving only the pilot binaries it builds. It reads what the stage did from the
// server's own words, not from the stage's: the rules by `ipa hbacrule-find` (the CLI, not the engine's reads), the
// writes by the server's log, the authorization by `ipa hbactest` and by a real ssh login on the client.
//
// It runs when PILOT_IDENTITY_ENGINE_LIVE_HBAC names the enrolled snapshot of the two VMs, and takes the rest of its
// environment from TestLiveGoApplyDriver (PILOT_IDENTITY_ENGINE_LIVE_APPLY is replaced by it). The baseline arm A1 of
// that driver runs first (the roster applied by the Ansible engine and acknowledged, then the paired snapshot every other
// arm starts from); it is always selected. PILOT_IDENTITY_ENGINE_LIVE_ARMS selects arms by prefix, as there.
//
// The roster is the Phase 2 base roster (applyDriver.baseRoster): users with the oracle key, the hostgroup of the
// client, a rule that grants them ssh to it, a break-glass rule of admin, and the lockdown of allow_all.
func TestLiveHBACDriver(t *testing.T) {
	base := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_HBAC")
	if base == "" {
		t.Skip("PILOT_IDENTITY_ENGINE_LIVE_HBAC is not set")
	}
	lv := newLiveLab(t, base)
	summary := &applySummary{Revision: gitOut(t, lv.repo, "rev-parse", "HEAD"), Tree: gitOut(t, lv.repo, "rev-parse", "HEAD^{tree}"), BaseSnapshot: base, MaxBatch: MaxBatch}
	defer func() { writeApplySummary(t, summary) }()
	want := map[string]bool{}
	for _, a := range strings.Split(os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_ARMS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			want[a] = true
		}
	}
	selected := func(name string) bool {
		if len(want) == 0 || strings.HasPrefix(name, "A1") {
			return true
		}
		for w := range want {
			if strings.HasPrefix(name, w) {
				return true
			}
		}
		return false
	}
	d := &applyDriver{lv: lv, summary: summary, selected: selected, pws: map[string]string{}}
	d.runHBAC()
	for _, arm := range summary.Arms {
		if !arm.Pass && !arm.Skipped {
			t.Errorf("arm %s failed: %s", arm.Name, strings.Join(arm.Failures, "; "))
		}
	}
}

// ---- what the server says ----

// liveRule is one HBAC rule as `ipa hbacrule-find --all --raw` prints it.
type liveRule struct {
	Enabled                                    bool
	HostCat, ServiceCat, UserCat               string
	Users, Groups, Hosts, Hostgroups, Services []string
}

// parseLiveRules reads the raw output of hbacrule-find --all: an entry begins at its cn, a member is a DN
// whose container says what it is.
func parseLiveRules(out string) map[string]liveRule {
	rules := map[string]liveRule{}
	var cur string
	flush := func(r liveRule) {
		if cur == "" {
			return
		}
		for _, l := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.Hostgroups, &r.Services} {
			sort.Strings(*l)
		}
		rules[strings.ToLower(cur)] = r
	}
	var r liveRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "cn":
			flush(r)
			cur, r = v, liveRule{}
		case "ipaenabledflag":
			r.Enabled = strings.EqualFold(v, "TRUE")
		case "hostcategory":
			r.HostCat = v
		case "servicecategory":
			r.ServiceCat = v
		case "usercategory":
			r.UserCat = v
		case "memberuser", "memberhost", "memberservice":
			first, rest, _ := strings.Cut(v, ",")
			_, name, _ := strings.Cut(first, "=")
			name = strings.ToLower(name)
			switch {
			case strings.Contains(rest, "cn=hostgroups"):
				r.Hostgroups = append(r.Hostgroups, name)
			case strings.Contains(rest, "cn=computers"):
				r.Hosts = append(r.Hosts, name)
			case strings.Contains(rest, "cn=hbacservices"):
				r.Services = append(r.Services, name)
			case strings.Contains(rest, "cn=groups"):
				r.Groups = append(r.Groups, name)
			default:
				r.Users = append(r.Users, name)
			}
		}
	}
	flush(r)
	return rules
}

// liveHBAC reads the rules of the server through the ipa CLI, which is not the engine's reader.
func (a *armCtx) liveHBAC() (map[string]liveRule, bool) {
	out, err := a.lv.ipaCLI("ipa hbacrule-find --all --raw --sizelimit=0")
	if err != nil {
		a.fail("ipa hbacrule-find: %v\n%s", err, tail(out, 600))
		return nil, false
	}
	return parseLiveRules(out), true
}

// toMaps reads a roster list of mappings, whether it was built typed or came back through JSON.
func toMaps(v any) []map[string]any {
	switch l := v.(type) {
	case []map[string]any:
		return l
	case []any:
		var out []map[string]any
		for _, e := range l {
			out = append(out, e.(map[string]any))
		}
		return out
	}
	return nil
}

func rosterStrs(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		var out []string
		for _, e := range l {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func hbacSection(r rosterDoc) map[string]any { return asMap(r["hbac"]) }

// ruleOf is the named HBAC rule of a roster (as written), for a mutation.
func ruleOf(r rosterDoc, name string) map[string]any {
	for _, m := range toMaps(hbacSection(r)["rules"]) {
		if strings.EqualFold(fmt.Sprint(m["name"]), name) {
			return m
		}
	}
	panic("no HBAC rule " + name)
}

// addRule appends a rule to the roster's hbac section.
func addRule(r rosterDoc, rule map[string]any) {
	raw, _ := json.Marshal(rule)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	h := hbacSection(r)
	h["rules"] = append(anyList(h["rules"]), m)
}

func anyList(v any) []any {
	var out []any
	for _, m := range toMaps(v) {
		out = append(out, m)
	}
	return out
}

func subjectsOf(rule map[string]any) map[string]any { return asMap(rule["subjects"]) }
func targetsOf(rule map[string]any) map[string]any  { return asMap(rule["targets"]) }

// expectedRules is what the roster says FreeIPA has: the rules that are not absent, as the server prints them,
// and the names of those marked absent.
func expectedRules(r rosterDoc) (map[string]liveRule, []string) {
	want := map[string]liveRule{}
	var absent []string
	for _, m := range toMaps(hbacSection(r)["rules"]) {
		name := strings.ToLower(fmt.Sprint(m["name"]))
		if m["state"] == "absent" {
			absent = append(absent, name)
			continue
		}
		enabled := true
		if e, ok := m["enabled"].(bool); ok {
			enabled = e
		}
		rule := liveRule{Enabled: enabled}
		low := func(l []string) []string {
			out := []string{}
			for _, s := range l {
				out = append(out, strings.ToLower(s))
			}
			sort.Strings(out)
			return out
		}
		rule.Users, rule.Groups = low(rosterStrs(subjectsOf(m)["users"])), low(rosterStrs(subjectsOf(m)["groups"]))
		rule.Hosts, rule.Hostgroups = low(rosterStrs(targetsOf(m)["hosts"])), low(rosterStrs(targetsOf(m)["hostgroups"]))
		rule.Services = low(rosterStrs(m["services"]))
		if targetsOf(m)["hostcat"] == "all" {
			rule.HostCat = "all"
		}
		want[name] = rule
	}
	return want, absent
}

func norm(l []string) []string {
	if len(l) == 0 {
		return []string{}
	}
	return l
}

// hbacConverged reads the server and requires every roster rule to be there as the roster says, and no rule the
// roster marks absent.
func (a *armCtx) hbacConverged(r rosterDoc, label string) bool {
	live, ok := a.liveHBAC()
	if !ok {
		return false
	}
	want, absent := expectedRules(r)
	good := true
	for name, w := range want {
		got, ok := live[name]
		if !ok {
			a.fail("%s: rule %s is not on the server", label, name)
			good = false
			continue
		}
		if got.Enabled != w.Enabled || got.HostCat != w.HostCat || got.ServiceCat != "" || got.UserCat != "" ||
			!slices.Equal(norm(got.Users), norm(w.Users)) || !slices.Equal(norm(got.Groups), norm(w.Groups)) ||
			!slices.Equal(norm(got.Hosts), norm(w.Hosts)) || !slices.Equal(norm(got.Hostgroups), norm(w.Hostgroups)) ||
			!slices.Equal(norm(got.Services), norm(w.Services)) {
			a.fail("%s: rule %s is %+v on the server, the roster says %+v", label, name, got, w)
			good = false
		}
	}
	for _, name := range absent {
		if _, ok := live[name]; ok {
			a.fail("%s: rule %s is on the server and the roster marks it absent", label, name)
			good = false
		}
	}
	return good
}

func (a *armCtx) allowAllEnabled() bool {
	live, ok := a.liveHBAC()
	if !ok {
		return false
	}
	return live["allow_all"].Enabled
}

// hbactest asks the server (the CLI) whether user may log in to the client over service.
func (a *armCtx) hbactest(user, service string) bool {
	out, _ := a.lv.ipaCLI(fmt.Sprintf("ipa hbactest --user=%s --host=%s --service=%s", user, a.lv.cliFQDN, service))
	return strings.Contains(out, "Access granted: True")
}

// waitLogin polls a real ssh login of user to the client until it gives the answer wanted, and says how long it
// took. HBAC reaches the client through SSSD's own refresh of its rules; nothing here clears a cache.
func (a *armCtx) waitLogin(user string, want bool, within time.Duration) (time.Duration, bool) {
	start := time.Now()
	for {
		if a.lv.loginKey(user, "true") == want {
			return time.Since(start), true
		}
		if time.Since(start) > within {
			return time.Since(start), false
		}
		time.Sleep(3 * time.Second)
	}
}

// ---- what the server logged ----

var hbacWriteMethod = regexp.MustCompile(`\b(hbacsvc_add|hbacrule_add|hbacrule_mod|hbacrule_del|hbacrule_add_host|hbacrule_remove_host|hbacrule_add_user|hbacrule_remove_user|hbacrule_add_service|hbacrule_remove_service|hbacrule_enable|hbacrule_disable)(?:/\d+)?\(`)

// hbacWritesSince is the HBAC write commands the server logged since offset, in order, by method. A batched write
// is logged as "batch: <method>(...)" and again as "batch(<method>(...))" for the session; the first counts.
func (a *armCtx) hbacWritesSince(offset int64) []string {
	out, err := sshRun(a.lv.srv, fmt.Sprintf("tail -c +%d %s", offset+1, serverLog))
	if err != nil {
		a.fail("read the server log: %v", err)
		return nil
	}
	return countHBACWrites(out)
}

// countHBACWrites is the HBAC write methods of server log text, in order.
func countHBACWrites(log string) []string {
	var methods []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "batch(") {
			continue
		}
		if m := hbacWriteMethod.FindStringSubmatch(line); m != nil {
			methods = append(methods, m[1])
		}
	}
	return methods
}

// hRun is a mixed run with the HBAC writes the server logged during it.
type hRun struct {
	applyRun
	HBACWrites []string
}

// mixedH runs the mixed command and reads the HBAC writes at once, before anything else of the arm writes.
func (a *armCtx) mixedH(ws string, extra ...string) hRun {
	a.lv.t.Helper()
	r := a.mixed(ws, extra...)
	h := hRun{applyRun: r, HBACWrites: a.hbacWritesSince(r.LogFrom)}
	runs, _ := a.facts["runs"].([]map[string]any)
	if n := len(runs); n > 0 {
		runs[n-1]["hbac_writes"] = h.HBACWrites
		if r.HasDoc && r.Doc.HBAC != nil {
			runs[n-1]["hbac"] = hbacFacts(r.Doc.HBAC)
		}
	}
	return h
}

func hbacFacts(h *HBACReport) map[string]any {
	f := map[string]any{"ran": h.Ran, "skipped": h.Skipped, "error": h.Error, "stats": h.Stats}
	if h.Result != nil {
		var ops []string
		for _, o := range h.Result.Ops {
			ops = append(ops, fmt.Sprintf("%s %s: %s", o.Operation.Kind, o.Operation.Object, o.Final()))
		}
		f["operations"] = ops
		f["verify_ok"] = h.Result.Verify.OK()
		if h.Result.Lockdown != nil {
			f["lockdown"] = h.Result.Lockdown
		}
	}
	return f
}

// hbacOps are the operations the stage ran, as "kind object", sorted.
func (h hRun) hbacOps() []string {
	if !h.HasDoc || h.Doc.HBAC == nil || h.Doc.HBAC.Result == nil {
		return nil
	}
	var out []string
	for _, o := range h.Doc.HBAC.Result.Ops {
		out = append(out, o.Operation.Kind+" "+o.Operation.Object)
	}
	sort.Strings(out)
	return out
}

// stageOK requires the run to have ended 0, the stage to have run, every operation to have succeeded and the read
// after the writes to be clean.
func (a *armCtx) stageOK(h hRun) bool {
	if !a.exit(h.applyRun, 0) {
		return false
	}
	if !a.ok(h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Ran && h.Doc.HBAC.Result != nil, "the result file has no HBAC stage that ran: %+v", h.Doc.HBAC) {
		return false
	}
	res := h.Doc.HBAC.Result
	good := a.ok(res.Observed && res.Stop == nil, "the stage stopped: %+v", res.Stop)
	for _, o := range res.Ops {
		good = a.ok(o.Final() == OutcomeSuccess || o.Final() == OutcomeNoop, "%s %s ended %s: %s %s", o.Operation.Kind, o.Operation.Object, o.Final(), o.Error, o.Detail) && good
	}
	if len(res.Ops) > 0 {
		good = a.ok(res.Verify.Done && res.Verify.OK(), "the read after the writes is not clean: %+v", res.Verify) && good
	}
	return good
}

// goPhaseQuiet requires the Go users and groups phase of a run to have had nothing to do and to have written
// nothing. The server's log also holds the identity playbook's own writes (it sets the users' ssh keys with user_mod on
// every run, whatever the roster says), which are not the Go engine's, so the log is a fact and not the test.
func (a *armCtx) goPhaseQuiet(h hRun, what string) bool {
	a.fact("server_user_group_writes_during_"+strings.NewReplacer(" ", "_").Replace(what), h.Writes)
	return a.ok(h.HasDoc && len(h.Doc.Plan1.Operations) == 0 && h.Doc.Stats.Writes == 0,
		"%s: the Go users and groups phase planned %d operations and wrote %d times", what, len(h.Doc.Plan1.Operations), h.Doc.Stats.Writes)
}

// noHBACWork requires the run to have written nothing HBAC: no operation and no HBAC command on the server.
func (a *armCtx) noHBACWork(h hRun, what string) bool {
	return a.ok(h.ExitCode == 0 && h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Ran && len(h.hbacOps()) == 0 && len(h.HBACWrites) == 0,
		"%s: exit %d, HBAC operations %v, HBAC writes on the server %v\n%s", what, h.ExitCode, h.hbacOps(), h.HBACWrites, tail(h.Out, 800))
}

// hasOps requires each wanted "kind object" among the stage's operations.
func (a *armCtx) hasOps(h hRun, want ...string) bool {
	got := h.hbacOps()
	good := true
	for _, w := range want {
		if !slices.Contains(got, w) {
			a.fail("the stage's operations %v lack %q", got, w)
			good = false
		}
	}
	return good
}

// previewFull is the read-only preview of the mixed run and the plan document it left.
func (a *armCtx) previewFull(ws string) (pilotResult, Document, bool) {
	plan := filepath.Join(a.lv.tmp, fmt.Sprintf("plan-full-%d.json", time.Now().UnixNano()))
	r := a.lv.runPilot(a.lv.pilot, a.data, []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--scope", "full", "--preview-only", "--plan-out", plan, "--timeout", "10m"})
	var doc Document
	data, err := os.ReadFile(plan)
	if err == nil && json.Unmarshal(data, &doc) == nil {
		return r, doc, true
	}
	return r, doc, false
}

// legacyRun is the Ansible engine's whole reconcile, with its output.
func (a *armCtx) legacyRun(ws string) pilotResult {
	return a.lv.runPilot(a.lv.pilot, a.data, []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--force"})
}

// hbacTaskNames are the identity playbook's tasks that are about the roster's HBAC, by name.
func hbacTaskNames(repo string) []string {
	raw, err := os.ReadFile(filepath.Join(repo, "playbooks", "apply", "freeipa-identity-apply.yml"))
	if err != nil {
		panic(err)
	}
	var names []string
	re := regexp.MustCompile(`(?m)^\s*- name: (.*)$`)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		n := strings.Trim(strings.TrimSpace(m[1]), `"'`)
		if strings.Contains(n, "HBAC") || strings.Contains(n, "allow_all") || strings.Contains(n, "break-glass") {
			names = append(names, n)
		}
	}
	return names
}

// ---- the roster of the arms ----

// hbacBase is the roster every arm starts from: the Phase 2 base roster, which the baseline applied.
func (d *applyDriver) hbacBase() rosterDoc {
	return d.mutate(d.baseRoster("admin"), func(rosterDoc) {})
}

const loginWait = 90 * time.Second

func (d *applyDriver) runHBAC() {
	lv, t := d.lv, d.lv.t
	d.runA1()
	if d.ackedTag == "" {
		t.Log("no acked baseline: the other arms cannot run")
		return
	}
	t.Cleanup(func() { lv.deleteSnapshot(d.ackedTag) })
	d.runH0()
	d.runH1()
	d.runH2()
	d.runH3()
	d.runH4()
	d.runH5()
	d.runH6()
	d.runH7()
	d.runH8()
	d.runH9()
	d.runH10()
	d.runH11()
}

// H0: Ansible converged first, and the Go stage finds nothing to do (spec §8.2, "反向"); what the full run costs
// when nothing changes, next to the Ansible engine's own run.
func (d *applyDriver) runH0() {
	d.arm("H0 the Ansible engine converged first: the Go plan has nothing to write", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := a.lv.copyWorkspace(d.hbacBase(), "", nil)
		pr, doc, ok := a.previewFull(ws)
		if a.ok(pr.ExitCode == 0 && ok && doc.HBAC != nil, "the full preview: exit %d\n%s", pr.ExitCode, tail(pr.Out, 800)) {
			a.ok(len(doc.HBAC.Operations) == 0 && len(doc.HBAC.Blocked) == 0 && len(doc.Operations) == 0, "the preview of the converged roster has operations %v %v and blocked %v", opKinds(doc.Operations), opKinds(doc.HBAC.Operations), doc.HBAC.Blocked)
			a.fact("preview_seconds", pr.Seconds)
		}
		h := a.mixedH(ws)
		a.noHBACWork(h, "the full run of a roster the Ansible engine applied")
		a.goPhaseQuiet(h, "the full run of a roster the Ansible engine applied")
		a.ok(!a.lv.journal().Pending, "the journal says an obligation is owed after a converged full run")
		a.fact("full_converged_seconds", h.Seconds)
		legacy := a.legacyRun(ws)
		a.ok(legacy.ExitCode == 0, "the Ansible engine's converged run exited %d", legacy.ExitCode)
		a.fact("ansible_converged_seconds", legacy.Seconds)
		a.hbacConverged(d.hbacBase(), "after the converged full run")
	})
}

// H1: the first run of a roster on a server that has none of it, through the mixed run: the hostgroup the playbook
// creates and the rule that refers to it in one run (D1), the lockdown, the roster's own users on the client, then
// the run again, and the Ansible engine on the state the Go stage made.
func (d *applyDriver) runH1() {
	d.arm("H1 from nothing: the hostgroup and the rule in one run, the lockdown, then Ansible agrees", func(a *armCtx) {
		if err := a.lv.rollback(a.lv.baseTag); err != nil {
			a.fail("rollback to the enrolled snapshot: %v", err)
			return
		}
		a.ok(a.allowAllEnabled(), "allow_all is not enabled on the enrolled server")
		roster := d.hbacBase()
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.stageOK(h)
		a.hasOps(h, "hbac.rule.create p26-ssh", "hbac.rule.create p26-admin", "hbac.allow_all.disable allow_all")
		if h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Result != nil {
			l := h.Doc.HBAC.Result.Lockdown
			if a.ok(l != nil, "the stage has no lockdown report") {
				a.ok(l.Before == "granted" && l.After == "granted" && l.Disabled && l.Rollback == "", "the lockdown report is %+v", *l)
				a.fact("lockdown", *l)
			}
		}
		a.ok(h.HasDoc && h.Doc.Playbook != nil, "the result file has no playbook account")
		a.hbacConverged(roster, "after the first full run")
		a.ok(!a.allowAllEnabled(), "allow_all is still enabled after the lockdown")
		a.ok(a.hbactest("admin", "sshd"), "admin is not granted sshd on the client after the lockdown (the break-glass rule)")
		a.ok(a.hbactest("p26-eve", "sshd"), "p26-eve, a rule member, is not granted sshd")
		a.ok(strings.Contains(a.serverHas("ipa hostgroup-show p26-targets 2>&1"), "p26-targets"), "the hostgroup is not on the server")
		took, ok := a.waitLogin("p26-ann", true, loginWait)
		a.ok(ok, "p26-ann cannot log in to the client although the rule grants it (waited %v)", took)
		a.fact("login_ann_seconds", took.Seconds())
		a.ok(!a.lv.journal().Pending, "the journal says an obligation is owed after the run")

		again := a.mixedH(ws)
		a.noHBACWork(again, "the same full run again")
		a.goPhaseQuiet(again, "the same full run again")

		legacy := a.legacyRun(ws)
		a.ok(legacy.ExitCode == 0, "the Ansible engine's run exited %d:\n%s", legacy.ExitCode, tail(legacy.Out, 1500))
		changed, seen := changedTasks(legacy.Out, hbacTaskNames(a.lv.repo))
		a.ok(seen > 0 && len(changed) == 0, "the Ansible engine's HBAC tasks after the Go stage: %d seen, changed %v", seen, changed)
		a.fact("ansible_hbac_tasks_seen", seen)
		a.hbacConverged(roster, "after the Ansible engine ran on the Go state")
	})
}

// H2: the login oracle. A user the rule grants logs in over ssh to the client; taken out of the rule, denied; the
// rule disabled, denied; enabled, granted; the rule deleted, denied (spec §8.2). Each step is one full run.
func (d *applyDriver) runH2() {
	d.arm("H2 the client's login follows the rule: removed, disabled, enabled, deleted", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		for _, u := range []string{"p26-ann", "p26-ben"} {
			_, ok := a.waitLogin(u, true, loginWait)
			a.ok(ok, "%s cannot log in before any change", u)
		}
		roster := d.hbacBase()
		ws := a.lv.copyWorkspace(roster, "", nil)
		step := func(name string, change func(r rosterDoc), ops []string, denied, granted []string) {
			change(roster)
			a.lv.setRoster(ws, roster)
			h := a.mixedH(ws)
			a.stageOK(h)
			a.hasOps(h, ops...)
			a.hbacConverged(roster, name)
			for _, u := range denied {
				took, ok := a.waitLogin(u, false, loginWait)
				a.ok(ok, "%s: %s can still log in (waited %v)", name, u, took)
				a.fact(name+" denied "+u+" after seconds", took.Seconds())
			}
			for _, u := range granted {
				took, ok := a.waitLogin(u, true, loginWait)
				a.ok(ok, "%s: %s cannot log in (waited %v)", name, u, took)
			}
		}
		step("annTakenOut", func(r rosterDoc) {
			rule := ruleOf(r, "p26-ssh")
			var keep []string
			for _, u := range rosterStrs(subjectsOf(rule)["users"]) {
				if u != "p26-ann" {
					keep = append(keep, u)
				}
			}
			subjectsOf(rule)["users"] = keep
		}, []string{"hbac.rule.member_user.remove p26-ssh"}, []string{"p26-ann"}, []string{"p26-ben"})
		step("ruleDisabled", func(r rosterDoc) { ruleOf(r, "p26-ssh")["enabled"] = false },
			[]string{"hbac.rule.disable p26-ssh"}, []string{"p26-ben"}, nil)
		step("ruleEnabled", func(r rosterDoc) { ruleOf(r, "p26-ssh")["enabled"] = true },
			[]string{"hbac.rule.enable p26-ssh"}, nil, []string{"p26-ben"})
		step("ruleDeleted", func(r rosterDoc) { ruleOf(r, "p26-ssh")["state"] = "absent" },
			[]string{"hbac.rule.delete p26-ssh"}, []string{"p26-ben"}, nil)
	})
}

// H3: the removal and transition paths: members taken out, the category switched both ways, a rule the roster does
// not name left alone, a name that differs by case, and an absent rule that was never there (spec §8.2, AGENTS.md §5.14).
func (d *applyDriver) runH3() {
	d.arm("H3 removals, category both ways, unlisted rule kept, case, absent that never was", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.hbacBase()
		ws := a.lv.copyWorkspace(roster, "", nil)
		run := func(name string, change func(r rosterDoc), ops ...string) hRun {
			change(roster)
			a.lv.setRoster(ws, roster)
			h := a.mixedH(ws)
			a.stageOK(h)
			a.hasOps(h, ops...)
			a.hbacConverged(roster, name)
			return h
		}
		run("membersAdded", func(r rosterDoc) {
			rule := ruleOf(r, "p26-ssh")
			subjectsOf(rule)["groups"] = []string{"team-p26"}
			targetsOf(rule)["hosts"] = []string{a.lv.cliFQDN}
			rule["services"] = []string{"sshd", "sudo", "su"}
		}, "hbac.rule.member_group.add p26-ssh", "hbac.rule.member_host.add p26-ssh", "hbac.rule.member_service.add p26-ssh")
		// A host is the same host in any spelling the server completes to its FQDN (spec §3.2, K4): the upper-case FQDN
		// and the short name both name the member that is there, and the stage writes nothing.
		for _, spelling := range []string{strings.ToUpper(a.lv.cliFQDN), strings.TrimSuffix(a.lv.cliFQDN, ".ipa.pilot.internal")} {
			targetsOf(ruleOf(roster, "p26-ssh"))["hosts"] = []string{spelling}
			a.lv.setRoster(ws, roster)
			hh := a.mixedH(ws)
			a.noHBACWork(hh, "the member host spelled "+spelling)
		}
		targetsOf(ruleOf(roster, "p26-ssh"))["hosts"] = []string{a.lv.cliFQDN}
		run("membersRemoved", func(r rosterDoc) {
			rule := ruleOf(r, "p26-ssh")
			subjectsOf(rule)["users"] = []string{"p26-ann", "p26-ben"}
			subjectsOf(rule)["groups"] = []string{}
			targetsOf(rule)["hosts"] = []string{}
			rule["services"] = []string{"sshd"}
		}, "hbac.rule.member_user.remove p26-ssh", "hbac.rule.member_group.remove p26-ssh", "hbac.rule.member_host.remove p26-ssh", "hbac.rule.member_service.remove p26-ssh")
		run("hostgroupsToAllHosts", func(r rosterDoc) {
			t := targetsOf(ruleOf(r, "p26-ssh"))
			t["hostgroups"], t["hostcat"] = []string{}, "all"
		}, "hbac.rule.category.update p26-ssh", "hbac.rule.member_hostgroup.remove p26-ssh")
		run("allHostsToHostgroups", func(r rosterDoc) {
			t := targetsOf(ruleOf(r, "p26-ssh"))
			t["hostgroups"] = []string{"p26-targets"}
			delete(t, "hostcat")
		}, "hbac.rule.category.update p26-ssh", "hbac.rule.member_hostgroup.add p26-ssh")
		// A rule the roster does not name stays (no pruning), the roster's spelling of a rule differs by case, and an
		// absent rule that was never there is nothing.
		if out, err := a.lv.ipaCLI("ipa hbacrule-add p26-unlisted >/dev/null"); err != nil {
			a.fail("the unlisted rule: %v\n%s", err, tail(out, 400))
			return
		}
		pr, _, _ := a.previewFull(ws)
		a.ok(strings.Contains(pr.Out, "p26-unlisted"), "the preview does not say that the server has a rule the roster does not name:\n%s", tail(pr.Out, 800))
		ruleOf(roster, "p26-admin")["name"] = "P26-Admin"
		addRule(roster, map[string]any{"name": "p26-never", "state": "absent", "subjects": map[string]any{"users": []string{"p26-ann"}}, "targets": map[string]any{"hostgroups": []string{"p26-targets"}}, "services": []string{"sshd"}})
		a.lv.setRoster(ws, roster)
		h := a.mixedH(ws)
		a.noHBACWork(h, "a case-different name, an absent rule that never was and a rule the roster does not name")
		live, ok := a.liveHBAC()
		if ok {
			_, kept := live["p26-unlisted"]
			a.ok(kept, "the rule the roster does not name was deleted")
			_, renamed := live["P26-Admin"]
			a.ok(!renamed, "the rule was recreated under the new spelling")
		}
	})
}

// H4: drift is repaired and the second run writes nothing (spec §8.2, AGENTS.md §5.14).
func (d *applyDriver) runH4() {
	d.arm("H4 drift on the server is repaired and the second run writes nothing", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		drift := fmt.Sprintf("ipa hbacrule-add-user p26-ssh --users=admin >/dev/null && ipa hbacrule-remove-service p26-ssh --hbacsvcs=sudo >/dev/null && ipa hbacrule-add-host p26-ssh --hosts=%s >/dev/null && ipa hbacrule-disable p26-admin >/dev/null", a.lv.cliFQDN)
		if out, err := a.lv.ipaCLI(drift); err != nil {
			a.fail("the drift: %v\n%s", err, tail(out, 400))
			return
		}
		roster := d.hbacBase()
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.stageOK(h)
		a.hasOps(h, "hbac.rule.member_user.remove p26-ssh", "hbac.rule.member_service.add p26-ssh", "hbac.rule.member_host.remove p26-ssh", "hbac.rule.enable p26-admin")
		a.hbacConverged(roster, "after the repair")
		again := a.mixedH(ws)
		a.noHBACWork(again, "the run after the repair")
	})
}

// H5: the lockdown of an allow_all that is enabled again (spec §8.2): the proofs before and after, and the server's own word.
func (d *applyDriver) runH5() {
	d.arm("H5 lockdown: allow_all enabled again, disabled with the proofs", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		if out, err := a.lv.ipaCLI("ipa hbacrule-enable allow_all >/dev/null"); err != nil {
			a.fail("enable allow_all: %v\n%s", err, tail(out, 400))
			return
		}
		// No rule grants ftp to anyone: only allow_all does, so it is the oracle of the lockdown.
		a.ok(a.hbactest("p26-eve", "ftp"), "allow_all is enabled and p26-eve is still not granted ftp: the set-up did not take")
		ws := a.lv.copyWorkspace(d.hbacBase(), "", nil)
		h := a.mixedH(ws)
		a.stageOK(h)
		a.ok(slices.Equal(h.hbacOps(), []string{"hbac.allow_all.disable allow_all"}), "the stage's operations are %v, want only the lockdown", h.hbacOps())
		a.ok(slices.Equal(h.HBACWrites, []string{"hbacrule_disable"}), "the server logged HBAC writes %v, want one hbacrule_disable", h.HBACWrites)
		if h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Result != nil && h.Doc.HBAC.Result.Lockdown != nil {
			l := *h.Doc.HBAC.Result.Lockdown
			a.ok(l.Before == "granted" && l.After == "granted" && l.Disabled && l.Rollback == "", "the lockdown report is %+v", l)
			a.fact("lockdown", l)
		} else {
			a.fail("no lockdown report")
		}
		a.ok(!a.allowAllEnabled(), "allow_all is still enabled")
		a.ok(a.hbactest("admin", "sshd"), "admin is not granted sshd after the lockdown")
		a.ok(a.hbactest("p26-eve", "sshd"), "p26-eve, a member of the ssh rule, is not granted sshd after the lockdown")
		a.ok(!a.hbactest("p26-eve", "ftp"), "p26-eve is still granted ftp after the lockdown: allow_all is not what was disabled")
	})
}

// H6: the plan's gates fire against the live state, before anything is written (spec §8.2, AGENTS.md §5.12): each
// blocked reason is made from the live server or from a roster the validator accepts.
func (d *applyDriver) runH6() {
	d.arm("H6 each blocked plan stops the run with exit 3 and writes nothing", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		type blockedCase struct {
			name, reason string
			roster       func(r rosterDoc)
			live         string
			// refusal: the roster validator, which runs before the plan and is the Ansible engine's too, refuses the
			// roster (exit 1, no plan), so the plan's own gate is a second line this roster cannot reach.
			refusal string
		}
		cases := []blockedCase{
			{"a rule refers to a service nobody has", BlockedHBACReference, func(r rosterDoc) {
				ruleOf(r, "p26-ssh")["services"] = []string{"sshd", "p26-no-such-service"}
			}, "", ""},
			{"the break-glass rule refers to a service nobody has, so the lockdown has none", BlockedLockdownNoBreakGlass, func(r rosterDoc) {
				ruleOf(r, "p26-admin")["services"] = []string{"sshd", "p26-no-such-service"}
			}, "", ""},
			// The server refuses a user category on a rule that has users, so the rule is made with the category and no member.
			{"the rule's user category is all on the server and the roster gives it users", BlockedUserCategoryAll, func(r rosterDoc) {
				addRule(r, map[string]any{"name": "p26-catall", "subjects": map[string]any{"users": []string{"p26-ann"}}, "targets": map[string]any{"hostgroups": []string{"p26-targets"}}, "services": []string{"sshd"}})
			}, "ipa hbacrule-add p26-catall --usercat=all >/dev/null", ""},
			{"two rules whose names differ only in case", BlockedCaseCollision, func(r rosterDoc) {
				addRule(r, map[string]any{"name": "P26-SSH", "subjects": map[string]any{"users": []string{"p26-ann"}}, "targets": map[string]any{"hostgroups": []string{"p26-targets"}}, "services": []string{"sshd"}})
			}, "", ""},
			{"allow_all is marked absent", BlockedAllowAllDelete, func(r rosterDoc) {
				addRule(r, map[string]any{"name": "allow_all", "state": "absent", "subjects": map[string]any{"users": []string{"admin"}}, "targets": map[string]any{"hostcat": "all"}, "services": []string{"sshd"}})
			}, "", "cannot be deleted via state: absent"},
		}
		for i, c := range cases {
			if i > 0 && !a.fresh() {
				return
			}
			if c.live != "" {
				if out, err := a.lv.ipaCLI(c.live); err != nil {
					a.fail("%s: the live set-up: %v\n%s", c.name, err, tail(out, 400))
					continue
				}
			}
			roster := d.hbacBase()
			c.roster(roster)
			ws := a.lv.copyWorkspace(roster, "", nil)
			logAt, _ := serverLogSize(a.lv.srv)
			pr, doc, ok := a.previewFull(ws)
			if c.refusal != "" {
				a.ok(pr.ExitCode == 1 && !ok && strings.Contains(pr.Out, c.refusal), "%s: the preview exited %d, want the validator's refusal %q (exit 1, no plan)\n%s", c.name, pr.ExitCode, c.refusal, tail(pr.Out, 800))
				a.ok(len(a.hbacWritesSince(logAt)) == 0, "%s: the server logged an HBAC write during the preview", c.name)
				a.fact(c.name, map[string]any{"exit": pr.ExitCode, "refused_by": "the roster validator"})
				continue
			}
			if !a.ok(pr.ExitCode == 3 && ok && doc.HBAC != nil, "%s: the preview exited %d (want 3), plan %v\n%s", c.name, pr.ExitCode, ok, tail(pr.Out, 1000)) {
				continue
			}
			var reasons []string
			for _, b := range doc.HBAC.Blocked {
				reasons = append(reasons, b.Reason)
			}
			a.ok(slices.Contains(reasons, c.reason), "%s: the plan blocks %v, want %s", c.name, reasons, c.reason)
			a.ok(len(a.hbacWritesSince(logAt)) == 0, "%s: the server logged an HBAC write during the preview", c.name)
			a.fact(c.name, map[string]any{"exit": pr.ExitCode, "blocked": reasons})
		}
		// The same plan in an apply: exit 3, before the playbook, and nothing written.
		if !a.fresh() {
			return
		}
		roster := d.hbacBase()
		ruleOf(roster, "p26-ssh")["services"] = []string{"sshd", "p26-no-such-service"}
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.ok(h.ExitCode == 3, "the blocked apply exited %d (want 3)\n%s", h.ExitCode, tail(h.Out, 1200))
		a.ok(!strings.Contains(h.Out, "▶ 套用：ansible-playbook playbooks/apply/freeipa-identity-apply.yml"), "the identity playbook was started although the plan is blocked")
		a.ok(len(h.HBACWrites) == 0 && h.WriteN == 0, "a blocked apply wrote: HBAC %v, users/groups %v", h.HBACWrites, h.Writes)
	})
}

// H7: the lockdown that does not hold is rolled back (spec §8.2): the break-glass rule is enabled and names admin
// on every host, so the plan accepts it, but it grants ftp and not sshd, so the proof after the disable fails.
func (d *applyDriver) runH7() {
	d.arm("H7 lockdown rollback: the proof after the disable fails and allow_all is enabled again", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		if out, err := a.lv.ipaCLI("ipa hbacrule-enable allow_all >/dev/null"); err != nil {
			a.fail("enable allow_all: %v\n%s", err, tail(out, 400))
			return
		}
		roster := d.hbacBase()
		ruleOf(roster, "p26-admin")["services"] = []string{"ftp"}
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.ok(h.ExitCode == 1, "the run exited %d (want 1, a partial application)\n%s", h.ExitCode, tail(h.Out, 1500))
		if a.ok(h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Result != nil && h.Doc.HBAC.Result.Lockdown != nil, "the result file has no lockdown report") {
			l := *h.Doc.HBAC.Result.Lockdown
			a.ok(l.Before == "granted" && l.After == "denied" && l.Disabled && l.Rollback == "re-enabled", "the lockdown report is %+v, want granted, denied, disabled, re-enabled", l)
			a.fact("lockdown", l)
		}
		a.ok(a.allowAllEnabled(), "allow_all is not enabled after the rollback")
		last := h.HBACWrites
		a.ok(len(last) >= 2 && last[len(last)-2] == "hbacrule_disable" && last[len(last)-1] == "hbacrule_enable", "the server's last HBAC writes are %v, want the disable and then the enable", last)
		a.ok(a.hbactest("p26-eve", "sshd"), "p26-eve is not granted although allow_all is enabled again")
		live, ok := a.liveHBAC()
		if ok {
			a.ok(slices.Equal(live["p26-admin"].Services, []string{"ftp"}), "the break-glass rule's services are %v: the writes before the lockdown are kept, as the stage says", live["p26-admin"].Services)
		}
	})
}

// H8: the playbook's first run fails and the HBAC stage does not run (spec §8.2, §7.3): a user whose ssh key the
// server refuses, which the playbook (not the Go engine) sets, and a rule the stage would have created.
func (d *applyDriver) runH8() {
	d.arm("H8 the playbook's first run fails: the HBAC stage does not run", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.hbacBase()
		d.addUser(roster, d.user("p26-badkey", with("ssh_keys", map[string]any{"authoritative": true, "values": []string{"ssh-ed25519 not-a-key"}})))
		addRule(roster, map[string]any{"name": "p26-after-failure", "subjects": map[string]any{"users": []string{"p26-ann"}}, "targets": map[string]any{"hostgroups": []string{"p26-targets"}}, "services": []string{"sshd"}})
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.ok(h.ExitCode == 1, "the run exited %d (want 1)\n%s", h.ExitCode, tail(h.Out, 1500))
		if a.ok(h.HasDoc && h.Doc.HBAC != nil, "the result file has no hbac account") {
			a.ok(!h.Doc.HBAC.Ran && h.Doc.HBAC.Skipped != "", "the stage ran or says nothing: %+v", h.Doc.HBAC)
			a.fact("skipped", h.Doc.HBAC.Skipped)
		}
		a.ok(len(h.HBACWrites) == 0, "the server logged HBAC writes after the playbook failed: %v", h.HBACWrites)
		live, ok := a.liveHBAC()
		if ok {
			_, made := live["p26-after-failure"]
			a.ok(!made, "the rule of the stage that should not have run is on the server")
		}
		second := strings.Contains(h.Out, "第 2 次：--tags client-cache")
		a.ok(!second, "the second playbook run started after the first one failed")
		a.fact("second_run_started", second)
	})
}

// H9: the second playbook run fails (spec §7.3). The client is stopped when the HBAC stage has finished, so the
// settlement cannot reach it: pilot's availability check, which runs before anything is applied, would refuse a run
// that began with the client down (and does: the arm's first attempt ended there, at exit 1, with nothing written).
// The HBAC stage has written by then, and what is reported is what happened.
func (d *applyDriver) runH9() {
	d.arm("H9 the second playbook run fails: the client is unreachable for the settlement", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.hbacBase()
		ruleOf(roster, "p26-ssh")["enabled"] = false
		ws := a.lv.copyWorkspace(roster, "", nil)
		virsh := func(verb string) error {
			out, err := exec.Command("virsh", verb, a.lv.cliVM).CombinedOutput()
			if err != nil {
				return fmt.Errorf("virsh %s: %v\n%s", verb, err, out)
			}
			return nil
		}
		defer func() { _ = virsh("resume") }()
		logAt, _ := serverLogSize(a.lv.srv)
		result := filepath.Join(a.lv.tmp, fmt.Sprintf("result-h9-%d.json", time.Now().UnixNano()))
		before, _ := exec.Command("ls", "-la", a.lv.cp).CombinedOutput()
		a.fact("control_dir_before_start", string(before))
		p := a.lv.startPilot(a.data, a.mixedArgs(ws, result))
		const stageDone = "接著執行第二次 playbook"
		deadline := time.Now().Add(20 * time.Minute)
		for !strings.Contains(p.out.String(), stageDone) {
			select {
			case <-p.done:
				after, _ := exec.Command("ls", "-la", a.lv.cp).CombinedOutput()
				a.fact("control_dir_after_end", string(after))
				a.fail("pilot ended (exit %d) before the HBAC stage finished:\n%s", p.exit, tail(p.out.String(), 1500))
				return
			case <-time.After(100 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				p.kill()
				a.fail("the HBAC stage did not finish in time")
				return
			}
		}
		if err := virsh("suspend"); err != nil {
			a.fail("%v", err)
		}
		res, err := p.wait(15 * time.Minute)
		if err != nil {
			a.fail("%v", err)
		}
		h := hRun{applyRun: a.collect(res, result, logAt)}
		h.HBACWrites = a.hbacWritesSince(logAt)
		a.fact("exit", h.ExitCode)
		a.fact("output_tail", tail(h.Out, 2500))
		a.ok(h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Ran && h.Doc.HBAC.Result != nil, "the stage did not run before the settlement")
		a.ok(slices.Contains(h.HBACWrites, "hbacrule_disable"), "the stage's disable was not logged: %v", h.HBACWrites)
		a.ok(h.ExitCode != 0, "the run exited 0 although the settlement could not reach the client:\n%s", tail(h.Out, 1500))
		if h.HasDoc {
			a.fact("authorization", h.Doc.Authorization)
			a.fact("verdict", h.Doc.Verdict+" "+h.Doc.Outcome+" at "+h.Doc.FailedStep)
		}
	})
}

// H10: a member the server refuses is a failed operation of the stage, the run is a partial application, and the
// settlement still runs (spec Q1: a rule that names a user the same roster marks absent).
func (d *applyDriver) runH10() {
	d.arm("H10 a rule names a user the roster deletes: the member fails, the run is partial, the settlement runs", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.hbacBase()
		subj := subjectsOf(ruleOf(roster, "p26-ssh"))
		subj["users"] = append(rosterStrs(subj["users"]), "p26-dan")
		find(roster, "users", "p26-dan")["state"] = "absent"
		// The users and groups plan refuses a group that lists a user the roster deletes (it would be a member of nothing):
		// the user leaves the group in the same roster, so the only reference left is the HBAC rule's.
		setMembers(roster, "team-p26", "p26-ann", "p26-ben", "p26-cat")
		ws := a.lv.copyWorkspace(roster, "", nil)
		h := a.mixedH(ws)
		a.ok(h.ExitCode == 1, "the run exited %d (want 1)\n%s", h.ExitCode, tail(h.Out, 1500))
		if a.ok(h.HasDoc && h.Doc.HBAC != nil && h.Doc.HBAC.Result != nil, "the result file has no HBAC result") {
			bad := 0
			for _, o := range h.Doc.HBAC.Result.Ops {
				if f := o.Final(); f != OutcomeSuccess && f != OutcomeNoop {
					bad++
				}
			}
			a.ok(bad > 0, "no operation failed: %v", h.hbacOps())
			a.fact("operations", hbacFacts(h.Doc.HBAC)["operations"])
		}
		a.ok(h.HasDoc && h.Doc.Playbook != nil, "no playbook account")
		a.fact("second_run_ran", strings.Contains(h.Out, "第 2 次：--tags client-cache"))
		a.ok(strings.Contains(h.Out, "第 2 次：--tags client-cache"), "the settlement run did not start after the stage failed")
	})
}

// H11: the playbook's own gate, run directly (spec §8.2, "每個新 gate 對 live 狀態真的觸發一次"): each wrong combination of
// the two new variables is refused before any task of the play, and the right one is not.
func (d *applyDriver) runH11() {
	d.arm("H11 the playbook's gate refuses a wrong engine or settle variable and passes the right ones", func(a *armCtx) {
		ws := a.lv.copyWorkspace(d.hbacBase(), "", nil)
		obs := filepath.Join(a.lv.tmp, "h11-observation.json")
		try := func(extra ...string) (int, string) {
			args := []string{filepath.Join(a.lv.repo, "playbooks", "apply", "freeipa-identity-apply.yml"), "-i", filepath.Join(ws, "inventory.yml"), "--limit", "ipa1",
				"-e", "stage=sandbox", "-e", "@" + filepath.Join(ws, ".vault", "main.yaml"), "--check", "--tags", "always"}
			cmd := exec.Command("ansible-playbook", append(args, extra...)...)
			cmd.Dir, cmd.Env = a.lv.repo, a.lv.pilotEnv()
			out, err := cmd.CombinedOutput()
			return exitCodeOf(err), string(out)
		}
		refused := []struct {
			name  string
			extra []string
		}{
			{"hbac engine go without the users/groups engine", []string{"-e", "pilot_identity_hbac_engine=go"}},
			{"settle defer without the hbac engine", []string{"-e", "pilot_identity_users_groups_engine=go", "-e", "pilot_identity_cache_settle=defer", "-e", "pilot_identity_auth_cache_output=" + obs}},
			{"an unknown settle value", []string{"-e", "pilot_identity_cache_settle=later"}},
			{"an unknown hbac engine", []string{"-e", "pilot_identity_hbac_engine=rust"}},
		}
		for _, c := range refused {
			code, out := try(c.extra...)
			a.ok(code != 0 && strings.Contains(out, "pilot_identity_hbac_engine must be ansible"), "%s: exit %d, the gate did not refuse it:\n%s", c.name, code, tail(out, 800))
			a.fact(c.name, code)
		}
		code, out := try("-e", "pilot_identity_users_groups_engine=go", "-e", "pilot_identity_hbac_engine=go", "-e", "pilot_identity_cache_settle=defer", "-e", "pilot_identity_auth_cache_output="+obs)
		a.ok(code == 0, "the right combination exited %d:\n%s", code, tail(out, 1000))
		a.fact("the right combination", code)
	})
}
