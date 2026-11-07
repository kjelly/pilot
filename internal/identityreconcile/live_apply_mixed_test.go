package identityreconcile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// The mixed arms of TestLiveGoApplyDriver (spec 2026-11-06 phase 2 §10.2, P2-7): A16, A17(iii)(iv) and H1 to
// H5 of `pilot reconcile --engine golang --scope full --force`, against the same two VMs and from the same acked
// baseline as the users-groups arms. A mixed run is the Ansible engine's whole reconcile path, so each of these
// includes the freeipa-server dependency's playbook and the identity playbook's own: a run takes minutes, and the
// arms that need a stop point use the identity_live_hooks build as the others do.
//
// What the arms assert is what the spec says each is for: the entry (the obligation recorded) before the first
// write; the client's cache refreshed by a full run and not by a users-groups one, said by the cache oracle of
// K20 and by the login oracle; the users and groups sections of the playbook skipped (its second run changes
// nothing in them, and a run that was cut never started it); the playbook never started when the Go phase did not
// finish; the exit codes; the result file; the lock and the journal after.

const mixedWait = 20 * time.Minute

func (a *armCtx) mixedArgs(ws, result string, extra ...string) []string {
	return append([]string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "full", "--result-out", result, "--timeout", "30m"}, extra...)
}

// mixed runs the mixed command to the end and reads what it left, as apply does for the users-groups scope.
func (a *armCtx) mixed(ws string, extra ...string) applyRun {
	a.lv.t.Helper()
	logAt, _ := serverLogSize(a.lv.srv)
	result := filepath.Join(a.lv.tmp, fmt.Sprintf("mixed-%s-%d.json", strings.NewReplacer("/", "-", " ", "-", "(", "", ")", "").Replace(a.name), time.Now().UnixNano()))
	r := a.lv.runPilot(a.lv.pilot, a.data, a.mixedArgs(ws, result, extra...), "PILOT_W_TEST_TOKEN=lab-token")
	return a.collect(r, result, logAt)
}

// serverHelperCalls counts the journal lines of the helper of the authorization cache journal (its argv names the
// journal file) since epoch: the entry playbook and the identity playbook both run it, and nothing else on the server
// does, so none since a point in time says neither of them ran.
func (a *armCtx) serverHelperCalls(since int64) int {
	out, _ := a.lv.onServer(fmt.Sprintf("journalctl --since @%d --no-pager 2>/dev/null | grep -c 'ssh-cache.json' || true", since))
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// usersGroupsTaskNames are the names of the identity playbook's tasks of the two ranges the Go engine owns, read from
// the playbook of the repository the driver runs from.
func (d *applyDriver) usersGroupsTaskNames() []string {
	raw, err := os.ReadFile(filepath.Join(d.lv.repo, "playbooks", "apply", "freeipa-identity-apply.yml"))
	if err != nil {
		d.lv.t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		d.lv.t.Fatal(err)
	}
	var block []any
	for _, t := range plays[0]["tasks"].([]any) {
		if inner, ok := t.(map[string]any)["block"].([]any); ok && len(inner) > 20 {
			block = inner
		}
	}
	var names []string
	in := false
	for _, t := range block {
		name, _ := t.(map[string]any)["name"].(string)
		switch name {
		case "List existing IPA groups", "Ensure user group membership":
			in = true
		}
		if in {
			names = append(names, name)
		}
		switch name {
		case "Gate: every password this run set was accepted", "Delete canonical groups explicitly marked absent":
			in = false
		}
	}
	return names
}

var taskHeader = regexp.MustCompile(`(?m)^TASK \[(.*?)\] \*+`)

// changedTasks parses ansible-playbook's default output: the tasks of names that reported a change, by name.
func changedTasks(out string, names []string) (changed []string, seen int) {
	idx := taskHeader.FindAllStringSubmatchIndex(out, -1)
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for i, m := range idx {
		name := out[m[2]:m[3]]
		if !want[name] {
			continue
		}
		seen++
		end := len(out)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		for _, line := range strings.Split(out[m[1]:end], "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "changed:") {
				changed = append(changed, name)
				break
			}
		}
	}
	sort.Strings(changed)
	return changed, seen
}

// revokedRoster is the roster of A6, the revocations the client's authorization follows (a removal from the sudo
// role group, a disabling, a user and a group deleted), without the grant that still names the deleted user: the
// identity playbook's grant task adds every user a rule names and fails on one that does not exist, and in a mixed run
// the Go phase has deleted the user before the playbook starts. (The Ansible engine meets the same task on the run
// after the deletion, which is what H2 and the dev runs of H1 showed; H6 is the arm that keeps the grant.)
func (d *applyDriver) revokedRoster(base func() rosterDoc) rosterDoc {
	return d.mutate(d.revokedKeepingGrants(base), func(r rosterDoc) { dropGrantTo(r, "p26-ssh", "p26-dan") })
}

// revokedKeepingGrants is A6's roster as it is: dan is absent and the HBAC rule p26-ssh still names him.
func (d *applyDriver) revokedKeepingGrants(base func() rosterDoc) rosterDoc {
	return d.mutate(base(), func(r rosterDoc) {
		setMembers(r, "role-p26")
		find(r, "users", "p26-ben")["state"] = "disabled"
		find(r, "users", "p26-dan")["state"] = "absent"
		find(r, "groups", "data-p26")["state"] = "absent"
		setMembers(r, "team-p26", "p26-ann", "p26-ben")
	})
}

// dropGrantTo removes user from the subjects of the HBAC rule.
func dropGrantTo(r rosterDoc, rule, user string) {
	for _, raw := range r["hbac"].(map[string]any)["rules"].([]any) {
		m := raw.(map[string]any)
		if m["name"] != rule {
			continue
		}
		subjects := m["subjects"].(map[string]any)
		var kept []any
		for _, u := range subjects["users"].([]any) {
			if u != user {
				kept = append(kept, u)
			}
		}
		subjects["users"] = kept
		return
	}
	panic("no rule " + rule)
}

var revocationWrites = map[string]int{"group_del": 1, "group_remove_member": 2, "user_del": 1, "user_disable": 1}

// warmClient makes the client hold ann's authorization (the revocation arms start from it, K20) and fails the arm
// when it does not.
func (a *armCtx) warmClient() bool {
	warm := a.lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
	ok := a.ok(warm.IDResolves && warm.InSudoGroup && warm.SudoListsRule, "the client does not hold ann's authorization before the revocation: %+v", warm)
	ok = a.ok(a.lv.loginKey("p26-ann", "sudo -n /usr/bin/true"), "ann cannot log in and sudo before the revocation") && ok
	return ok
}

// clientDenies asserts the client's authorization of ann was refreshed: the cache oracle (what SSSD holds, which only a
// refresh changes, K20) says the group and the rule are gone, and the login oracle denies the sudo.
func (a *armCtx) clientDenies() {
	cache := a.lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
	a.fact("client_cache_view_after", cache)
	a.ok(!cache.InSudoGroup && !cache.SudoListsRule, "the client's cache still holds ann's authorization: %+v (a refresh should have removed it)", cache)
	a.ok(!a.lv.loginKey("p26-ann", "sudo -n /usr/bin/true"), "ann can still log in and sudo")
}

// clientStillAllows asserts the cache oracle still shows ann's authorization: nothing refreshed the client.
func (a *armCtx) clientStillAllows() {
	cache := a.lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
	a.fact("client_cache_view_after", cache)
	a.ok(cache.InSudoGroup && cache.SudoListsRule, "the client's cache no longer holds ann's authorization although nothing refreshed it: %+v", cache)
}

// serverRevoked asserts the server holds what the revocation roster says.
func (a *armCtx) serverRevoked() {
	a.ok(!strings.Contains(a.serverHas("ipa group-show role-p26"), "p26-ann"), "ann is still in role-p26 on the server")
	a.ok(strings.Contains(a.serverHas("ipa user-show p26-ben"), "Account disabled: True"), "ben is not disabled on the server")
	a.ok(strings.Contains(a.serverHas("ipa user-show p26-dan 2>&1"), "not found"), "dan is still there")
	a.ok(strings.Contains(a.serverHas("ipa group-show data-p26 2>&1"), "not found"), "data-p26 is still there")
}

func (d *applyDriver) runMixed(base func() rosterDoc, oneUser func(string, ...func(map[string]any)) rosterDoc) {
	lv := d.lv

	// A16: a blocked plan ends the mixed run before the identity playbook has been asked anything. Its control is the
	// run of H1 below, whose helper calls on the server are what a run that did start the playbook leaves.
	d.arm("A16 a mixed run whose plan is blocked", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		blocked := d.mutate(base(), func(r rosterDoc) { find(r, "users", "p26-ann")["uid"] = 1927609999 })
		ws := lv.copyWorkspace(blocked, "", nil)
		since := time.Now().Unix()
		r := a.mixed(ws)
		a.exit(r, 3)
		a.ok(r.WriteN == 0, "a blocked mixed run wrote: %v", r.Writes)
		a.pending(false)
		a.ok(a.serverHelperCalls(since) == 0, "the helper of the authorization cache journal ran on the server (the entry or the identity playbook) in a run whose plan is blocked")
		a.ok(!strings.Contains(r.Out, "ansible-playbook --check --diff playbooks/apply/freeipa-identity-apply.yml"), "the identity playbook's preview ran after a blocked plan:\n%s", tail(r.Out, 1200))
		a.ok(!strings.Contains(r.Out, "ansible-playbook playbooks/apply/freeipa-identity-apply.yml"), "the identity playbook's apply ran after a blocked plan")
		a.ok(strings.Contains(r.Out, "阻擋"), "the blocked plan was not shown:\n%s", tail(r.Out, 800))
		a.ok(a.lockFree(30*time.Second), "the lock is not free after the run")
	})

	// H1: from the acked baseline, with the client's cache warm, the mixed run applies A6's revocations. The entry comes
	// first (the journal is owed and no revocation has been written when the run is held after it), the playbook then
	// acknowledges, and the client is refreshed: this is what A6, the users-groups run, did not do.
	var h1ws string
	d.arm("H1 a mixed run applies the revocations and refreshes the client", func(a *armCtx) {
		if !a.fresh() || !a.warmClient() {
			return
		}
		h1ws = lv.copyWorkspace(d.revokedRoster(base), "", nil)
		since := time.Now().Unix()
		logAt, _ := serverLogSize(lv.srv)
		result := filepath.Join(lv.tmp, "h1.json")
		p := lv.startPilot(a.data, a.mixedArgs(h1ws, result), "after_entry")
		n, err := p.waitNotify("after_entry", mixedWait)
		if err != nil {
			a.fail("%v", err)
			return
		}
		// The entry: owed on the server, and none of the revocations written yet.
		a.ok(lv.journal().Pending, "the journal is not owed at after_entry: the entry did not record the obligation first")
		w, _ := lv.writesSince(logAt)
		for _, m := range []string{"user_del", "user_disable", "group_del", "group_remove_member"} {
			a.ok(w[m] == 0, "%s was written before the entry's result was observed: %v", m, w)
		}
		p.answer(n, "resume")
		res, err := p.wait(mixedWait)
		if err != nil {
			a.fail("%v", err)
			return
		}
		r := a.collect(res, result, logAt)
		a.exit(r, 0)
		if r.HasDoc {
			a.ok(r.Doc.Scope == "full" && r.Doc.Verdict == VerdictOK && r.Doc.Playbook != nil && r.Doc.Playbook.Ran && r.Doc.Playbook.Observation != nil && r.Doc.Playbook.Observation.Acked && !r.Doc.Authorization.Owed && r.Doc.Entry.Ran,
				"the result file: scope %q verdict %q playbook %+v authorization %+v", r.Doc.Scope, r.Doc.Verdict, r.Doc.Playbook, r.Doc.Authorization)
			a.fact("verdict", r.Doc.Verdict)
			a.fact("observation", r.Doc.Playbook.Observation)
		}
		got := map[string]int{}
		for m, n := range r.Writes {
			if _, ok := revocationWrites[m]; ok {
				got[m] = n
			}
		}
		a.ok(fmt.Sprint(got) == fmt.Sprint(revocationWrites), "the revocation writes the server logged: %v, want %v (all writes %v)", got, revocationWrites, r.Writes)
		a.ok(a.serverHelperCalls(since) > 0, "the helper of the journal never ran on the server: the control of A16 shows nothing")
		a.serverRevoked()
		a.clientDenies()
		a.pending(false)
		// The Go engine, run again with nothing to change, reads the obligation settled.
		again := a.apply(h1ws)
		a.exit(again, 0)
		a.ok(again.HasDoc && len(again.Doc.Plan1.Operations) == 0 && !again.Doc.Entry.Ran && again.Doc.Entry.Pending != nil && !*again.Doc.Entry.Pending, "the users-groups run after the mixed run: %+v", again.Doc.Authorization)
	})

	// H2: the legacy full run after H1 changes nothing in the users and groups sections (the Go engine left them as the
	// playbook would have).
	d.arm("H2 the legacy full run after the mixed run changes nothing in users and groups", func(a *armCtx) {
		if h1ws == "" {
			a.fail("H1 did not run")
			return
		}
		a.ok(!lv.journal().Pending, "H1 did not end acked: H2 continues from it")
		r := lv.runPilot(lv.pilot, a.data, []string{"reconcile", "--dir", h1ws, "--component", "freeipa-identity", "--force"})
		a.exit(applyRun{pilotResult: r}, 0)
		names := d.usersGroupsTaskNames()
		changed, seen := changedTasks(r.Out, names)
		a.fact("users_groups_tasks_in_output", seen)
		a.ok(seen >= 30, "only %d of the %d tasks of the users and groups sections are in the output: the parse sees nothing", seen, len(names))
		a.ok(len(changed) == 0, "tasks of the users and groups sections changed in the legacy run after the mixed run: %v", changed)
		a.pending(false)
	})

	// H3: A6's revocations by the users-groups engine, which leaves the client allowed and the journal owed; then a mixed
	// run in which the Go engine has nothing to write: the playbook's own prepare reads the owed journal, refreshes and
	// acknowledges.
	d.arm("H3 a mixed run with nothing to write refreshes what a users-groups run left", func(a *armCtx) {
		if !a.fresh() || !a.warmClient() {
			return
		}
		ws := lv.copyWorkspace(d.revokedRoster(base), "", nil)
		first := a.apply(ws)
		a.exit(first, 4)
		a.pending(true)
		a.clientStillAllows()
		r := a.mixed(ws)
		a.exit(r, 0)
		a.ok(r.WriteN == r.Writes["user_mod"], "the mixed run's Go phase wrote: %v", r.Writes)
		if r.HasDoc {
			a.ok(len(r.Doc.Plan1.Operations) == 0 && !r.Doc.Entry.Ran && r.Doc.Playbook != nil && r.Doc.Playbook.Observation != nil && r.Doc.Playbook.Observation.Acked,
				"the result file: plan1 %d operations, entry ran %v, playbook %+v", len(r.Doc.Plan1.Operations), r.Doc.Entry.Ran, r.Doc.Playbook)
		}
		a.clientDenies()
		a.pending(false)
	})

	// H4: the same revocations with the playbook's refresh of the clients switched off: the obligation is not settled,
	// so exit 4, partial_failed, a failure for the webhook, and the client still holds the old authorization. With the
	// refresh switched on again, a mixed run with nothing to write settles it.
	d.arm("H4 a mixed run that cannot refresh the client is unsettled", func(a *armCtx) {
		if !a.fresh() || !a.warmClient() {
			return
		}
		ws := lv.copyWorkspace(d.revokedRoster(base), "", map[string]string{"ipa_identity_refresh_sssd_cache": "false"})
		recv := newReceiver()
		defer recv.srv.Close()
		d.webhookFor(ws, recv)
		r := a.mixed(ws)
		a.exit(r, 4)
		if r.HasDoc {
			a.ok(r.Doc.Verdict == VerdictUnsettled && r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "verify" && r.Doc.Authorization.Owed && r.Doc.Playbook != nil && r.Doc.Playbook.Ran &&
				(r.Doc.Playbook.Observation == nil || !r.Doc.Playbook.Observation.Acked),
				"the result file: verdict %q outcome %q step %q playbook %+v authorization %+v", r.Doc.Verdict, r.Doc.Outcome, r.Doc.FailedStep, r.Doc.Playbook, r.Doc.Authorization)
		}
		a.serverRevoked()
		a.clientStillAllows()
		a.pending(true)
		cls := a.failureClass(recv)
		a.ok(cls == "verify_failed", "the webhook's failure class is %q, want verify_failed", cls)
		a.fact("failure_class", cls)
		// Refresh on again: the roster is the same, so the Go engine has nothing to write and the playbook settles.
		ws2 := lv.copyWorkspace(d.revokedRoster(base), "", nil)
		r2 := a.mixed(ws2)
		a.exit(r2, 0)
		a.clientDenies()
		a.pending(false)
	})

	// H5: the Go engine writes and then the playbook fails: partial_failed, exit 1, and the write stays. The failure is
	// an SSH key the playbook sends to FreeIPA and FreeIPA refuses; the preview does not (it sends nothing), and the Go
	// engine only reads keys.
	d.arm("H5 the playbook fails after the Go writes", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.mutate(oneUser("p26-n5"), func(r rosterDoc) {
			find(r, "users", "p26-ann")["ssh_keys"] = map[string]any{"authoritative": true, "values": []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIinvalidinvalidinvalidinvalidinvalidinvalid p26-bad"}}
		})
		ws := lv.copyWorkspace(roster, "", nil)
		r := a.mixed(ws)
		a.exit(r, 1)
		if r.HasDoc {
			a.ok(r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "apply" && r.Doc.Verdict == VerdictPartial && r.Doc.Playbook != nil && r.Doc.Playbook.Ran && r.Doc.Committed(),
				"the result file: outcome %q step %q verdict %q playbook %+v committed %v", r.Doc.Outcome, r.Doc.FailedStep, r.Doc.Verdict, r.Doc.Playbook, r.Doc.Committed())
			a.fact("run", map[string]any{"outcome": r.Doc.Outcome, "failed_step": r.Doc.FailedStep, "verdict": r.Doc.Verdict})
		}
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-n5 2>&1"), "User login: p26-n5"), "the Go engine's write is not on the server")
		a.pending(true)
		a.ok(a.lockFree(30*time.Second), "the lock is not free after the run")
	})

	// H6: the Go engine deletes a user that a grant of the roster still names; the playbook's grant task fails on the
	// deleted user. The run is partial_failed at the apply, exit 1, the revocations stay and the obligation stays owed
	// (the entry recorded it); the roster without the grant then settles it with nothing left for the Go engine to write.
	d.arm("H6 a grant that names the deleted user fails the playbook, and the corrected roster settles it", func(a *armCtx) {
		if !a.fresh() || !a.warmClient() {
			return
		}
		ws := lv.copyWorkspace(d.revokedKeepingGrants(base), "", nil)
		r := a.mixed(ws)
		a.exit(r, 1)
		if r.HasDoc {
			a.ok(r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "apply" && r.Doc.Verdict == VerdictPartial && r.Doc.Playbook != nil && r.Doc.Playbook.Ran &&
				r.Doc.Playbook.Observation == nil && r.Doc.Committed() && r.Doc.Authorization.Owed,
				"the result file: outcome %q step %q verdict %q playbook %+v committed %v authorization %+v", r.Doc.Outcome, r.Doc.FailedStep, r.Doc.Verdict, r.Doc.Playbook, r.Doc.Committed(), r.Doc.Authorization)
		}
		a.serverRevoked()
		a.clientStillAllows()
		a.pending(true)
		fixed := lv.copyWorkspace(d.revokedRoster(base), "", nil)
		r2 := a.mixed(fixed)
		a.exit(r2, 0)
		a.ok(r2.WriteN == r2.Writes["user_mod"], "the mixed run after the correction wrote: %v", r2.Writes)
		a.clientDenies()
		a.pending(false)
	})

	// A17(iii): SIGINT in the Go phase of the mixed run, with a write sent and its answer unread: the write is unknown and
	// resolved by the read after the writes, the playbook never starts, and every record of the run is written.
	d.arm("A17(iii) SIGINT in the Go phase of a mixed run", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-n17c"), "", nil)
		recv := newReceiver()
		defer recv.srv.Close()
		d.webhookFor(ws, recv)
		result := filepath.Join(lv.tmp, "a17iii.json")
		logAt, _ := serverLogSize(lv.srv)
		p := lv.startPilot(a.data, a.mixedArgs(ws, result), "after_send:S3:1")
		if _, err := p.waitNotify("after_send:S3:1", mixedWait); err != nil {
			a.fail("%v", err)
			return
		}
		a.ok(a.waitWrite("user_add", logAt, 60*time.Second), "the server did not log the user_add")
		p.signal(syscall.SIGINT)
		res, err := p.wait(10 * time.Minute)
		if err != nil {
			a.fail("%v", err)
			return
		}
		r := a.collect(res, result, logAt)
		a.exit(r, 1)
		if r.HasDoc {
			o := a.opOf(r, "user.create:p26-n17c")
			a.ok(o.Outcome == OutcomeUnknown, "the in-flight write is %q, want unknown", o.Outcome)
			a.ok(r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "apply", "the run: outcome %q at %q, want partial_failed at apply (not evidence_failed)", r.Doc.Outcome, r.Doc.FailedStep)
			a.ok(r.Doc.Verify.Done, "the read after the writes was not attempted")
			a.ok(r.Doc.Playbook != nil && !r.Doc.Playbook.Ran, "the identity playbook ran after the signal: %+v", r.Doc.Playbook)
			a.fact("operation", map[string]any{"outcome": o.Outcome, "resolution": o.Resolution})
			a.fact("run", map[string]any{"outcome": r.Doc.Outcome, "failed_step": r.Doc.FailedStep, "verdict": r.Doc.Verdict})
		} else {
			a.fail("no result file")
		}
		a.ok(!strings.Contains(res.Out, "ansible-playbook playbooks/apply/freeipa-identity-apply.yml"), "the identity playbook's apply started after the signal")
		cls := a.failureClass(recv)
		a.ok(cls == "apply_failed", "the webhook's failure class is %q, want apply_failed", cls)
		a.fact("failure_class", cls)
		a.ok(a.lockFree(60*time.Second), "the lock is not free after the run")
		a.ok(r.WriteN == 1, "the server logged %d writes: %v", r.WriteN, r.Writes)
	})
	d.arm("A17(iii) a second Ctrl-C ends a mixed run at once", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-n17d"), "", nil)
		p := lv.startPilot(a.data, a.mixedArgs(ws, filepath.Join(lv.tmp, "a17iiib.json")), "after_send:S3:1")
		if _, err := p.waitNotify("after_send:S3:1", mixedWait); err != nil {
			a.fail("%v", err)
			return
		}
		p.signal(syscall.SIGINT)
		time.Sleep(300 * time.Millisecond)
		p.signal(syscall.SIGINT)
		res, err := p.wait(60 * time.Second)
		a.ok(err == nil, "pilot did not end within a minute of the second signal: %v", err)
		a.fact("exit", res.ExitCode)
		a.ok(a.lockFree(60*time.Second), "the lock is not free after the second signal")
	})

	// A17(iv): SIGINT in the playbook phase: ansible-playbook is killed, the Go engine's write stays, the run is
	// partial_failed at apply, and its records are written.
	d.arm("A17(iv) SIGINT in the playbook phase of a mixed run", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-n17e"), "", nil)
		recv := newReceiver()
		defer recv.srv.Close()
		d.webhookFor(ws, recv)
		result := filepath.Join(lv.tmp, "a17iv.json")
		logAt, _ := serverLogSize(lv.srv)
		p := lv.startPilot(a.data, a.mixedArgs(ws, result))
		apply := regexp.MustCompile(`freeipa-identity-apply\.yml`)
		var playbookPID int
		end := time.Now().Add(mixedWait)
		for time.Now().Before(end) && playbookPID == 0 {
			for pid, args := range p.children() {
				if apply.MatchString(args) && !strings.Contains(args, "--check") {
					playbookPID = pid
				}
			}
			select {
			case <-p.done:
				a.fail("pilot ended before the identity playbook's apply started:\n%s", tail(p.out.String(), 1500))
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
		if !a.ok(playbookPID != 0, "the identity playbook's apply never started") {
			p.kill()
			return
		}
		time.Sleep(8 * time.Second) // into its tasks
		p.signal(syscall.SIGINT)
		res, err := p.wait(10 * time.Minute)
		if err != nil {
			a.fail("%v", err)
			return
		}
		r := a.collect(res, result, logAt)
		a.exit(r, 1)
		a.ok(syscall.Kill(playbookPID, 0) != nil, "the identity playbook (pid %d) outlived the signal", playbookPID)
		if r.HasDoc {
			a.ok(r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "apply" && r.Doc.Verdict == VerdictPartial && r.Doc.Playbook != nil && r.Doc.Playbook.Ran && r.Doc.Committed(),
				"the result file: outcome %q step %q verdict %q playbook %+v committed %v", r.Doc.Outcome, r.Doc.FailedStep, r.Doc.Verdict, r.Doc.Playbook, r.Doc.Committed())
			a.fact("run", map[string]any{"outcome": r.Doc.Outcome, "failed_step": r.Doc.FailedStep, "verdict": r.Doc.Verdict})
		} else {
			a.fail("no result file")
		}
		cls := a.failureClass(recv)
		a.ok(cls == "apply_failed", "the webhook's failure class is %q, want apply_failed", cls)
		a.fact("failure_class", cls)
		a.ok(a.lockFree(60*time.Second), "the lock is not free after the run")
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-n17e 2>&1"), "User login: p26-n17e"), "the Go engine's write is not on the server")
		a.pending(true)
	})
}
