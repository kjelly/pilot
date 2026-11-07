package identityreconcile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The arms of TestLiveGoApplyDriver, in the order of spec §10.2. Each starts from the acked
// baseline (a rollback to the snapshot A1 takes, and a check that the journal is acked) unless it
// continues the arm before it, says what it does to the roster and the server, runs pilot, and
// asserts what the spec's table says of it: the exit code, the operations, what the server logged,
// what the journal and the client hold afterwards.

const (
	newUserOps = "user.create p26-new"
	hookWait   = 3 * time.Minute
)

func (d *applyDriver) runAll() {
	lv := d.lv
	t := lv.t
	d.runA1()
	if d.ackedTag == "" {
		t.Log("no acked baseline: the other arms cannot run")
		return
	}
	t.Cleanup(func() { lv.deleteSnapshot(d.ackedTag) })
	base := func() rosterDoc { return d.baseRoster("admin") }
	withNew := func(r rosterDoc) rosterDoc {
		return d.mutate(r, func(r rosterDoc) {
			d.addUser(r, d.user("p26-new"))
			d.addGroup(r, group("team-p26n", "team", []string{"p26-new"}, nil))
		})
	}
	oneUser := func(name string, opts ...func(map[string]any)) rosterDoc {
		return d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.user(name, opts...)) })
	}

	// A2, A3, A4 are one chain: each starts where the one before ended.
	var chainWS string
	var afterA2 journalState
	d.arm("A2 add a user and a group", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		chainWS = lv.copyWorkspace(withNew(base()), "", nil)
		r := a.apply(chainWS)
		a.exit(r, 4)
		a.opsAre(r, "group.create team-p26n", "group.marker.create "+HistoryMarkerName("team-p26n"), "user.create p26-new", "user.password.initialize p26-new", "group.member_user.add team-p26n")
		a.writesAre(r, map[string]int{"group_add": 2, "user_add": 1, "passwd": 1, "group_add_member": 1})
		a.verifyClean(r)
		if r.HasDoc {
			a.ok(r.Doc.Authorization.Owed && r.Doc.Authorization.Source == ObligationThisRun && r.Doc.Entry.Ran, "the entry did not run: %+v", r.Doc.Authorization)
			a.fact("verdict", r.Doc.Verdict)
			a.fact("outcome", r.Doc.Outcome+" at "+r.Doc.FailedStep)
			a.fact("stats", r.Doc.Stats)
		}
		a.pending(true)
		afterA2 = lv.journal()
	})
	d.arm("A3 the same run again", func(a *armCtx) {
		if chainWS == "" {
			a.fail("A2 did not run")
			return
		}
		r := a.apply(chainWS)
		a.exit(r, 4)
		a.ok(r.HasDoc && len(r.Doc.Plan1.Operations) == 0 && r.Doc.Stats.Writes == 0 && r.WriteN == 0, "the second run was not a zero-mutation run: %d writes, %v", r.WriteN, r.Writes)
		if r.HasDoc {
			a.ok(!r.Doc.Entry.Ran && r.Doc.Entry.Pending != nil && *r.Doc.Entry.Pending && r.Doc.Authorization.Source == ObligationPreviousRun, "the entry ran or the probe did not read pending: %+v", r.Doc.Authorization)
		}
		a.ok(lv.journal() == afterA2, "the journal changed: %+v -> %+v", afterA2, lv.journal())
	})
	d.arm("A4 a full run, then the Go run", func(a *armCtx) {
		if chainWS == "" {
			a.fail("A2 did not run")
			return
		}
		a.ok(a.legacy(chainWS), "the full legacy run failed")
		a.pending(false)
		before := lv.journal()
		r := a.apply(chainWS)
		a.exit(r, 0)
		if r.HasDoc {
			a.ok(!r.Doc.Entry.Ran && r.Doc.Entry.Pending != nil && !*r.Doc.Entry.Pending, "the entry ran or the probe found an obligation: %+v", r.Doc.Authorization)
			a.fact("verdict", r.Doc.Verdict)
		}
		a.ok(r.WriteN == 0, "the server logged writes: %v", r.Writes)
		a.ok(lv.journal() == before, "the journal bytes changed: %+v -> %+v", before, lv.journal())
	})

	d.arm("A2b a user created with an explicit uid and gid", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-uid", with("uid", 1927650001), with("gid", 1927650001)), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.create p26-uid", "user.password.initialize p26-uid")
		a.verifyClean(r)
		show := a.serverHas("ipa user-show p26-uid --all")
		a.ok(strings.Contains(show, "UID: 1927650001") && strings.Contains(show, "GID: 1927650001"), "the server did not take the uid and gid:\n%s", tail(show, 600))
		a.fact("server", "accepted uidnumber and gidnumber sent as JSON integers")
	})

	d.arm("A5 one attribute", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { find(r, "users", "p26-ann")["login_shell"] = "/bin/sh" }), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.update p26-ann")
		if r.HasDoc && len(executedPlan(r.Doc).Operations) == 1 {
			var fields []string
			for k := range executedPlan(r.Doc).Operations[0].Fields {
				fields = append(fields, k)
			}
			a.ok(len(fields) == 1 && fields[0] == "loginshell", "the user_mod carries %v, want only loginshell", fields)
		}
		a.writesAre(r, map[string]int{"user_mod": 1})
	})

	d.arm("A6 revocations: the server changes, the client's cache does not until it is refreshed", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		// Warm the client's cache with the real user, as K20 did, before the revocation.
		warm := lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
		a.ok(warm.IDResolves && warm.InSudoGroup && warm.SudoListsRule, "the client does not hold ann's authorization before the revocation: %+v", warm)
		a.ok(lv.loginKey("p26-ann", "sudo -n /usr/bin/true"), "ann cannot log in and sudo before the revocation")
		warm = lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) {
			setMembers(r, "role-p26")
			find(r, "users", "p26-ben")["state"] = "disabled"
			find(r, "users", "p26-dan")["state"] = "absent"
			find(r, "groups", "data-p26")["state"] = "absent"
			setMembers(r, "team-p26", "p26-ann", "p26-ben")
		}), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		if r.HasDoc {
			got := strings.Join(a.ops(r), "\n")
			for _, want := range []string{"group.member_user.remove role-p26", "group.member_user.remove team-p26", "user.disable p26-ben", "user.delete p26-dan", "group.delete data-p26"} {
				a.ok(strings.Contains(got, want), "the plan lacks %q:\n%s", want, got)
			}
			a.verifyClean(r)
			a.fact("verdict", r.Doc.Verdict)
		}
		// The server: revoked.
		a.ok(!strings.Contains(a.serverHas("ipa group-show role-p26"), "p26-ann"), "ann is still in role-p26 on the server")
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-ben"), "Account disabled: True"), "ben is not disabled on the server")
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-dan 2>&1"), "not found"), "dan is still there")
		a.ok(strings.Contains(a.serverHas("ipa group-show data-p26 2>&1"), "not found"), "data-p26 is still there")
		a.ok(!strings.Contains(a.serverHas("ipa group-show team-p26"), "p26-cat"), "cat is still in team-p26 (the shrinking member list)")
		// The client: the cache view still shows the old authorization; Go never refreshes (H1 and H3 are what does).
		cache := lv.cacheView("p26-ann", "role-p26", "/usr/bin/true")
		a.fact("client_cache_view_after_go", cache)
		a.ok(cache.InSudoGroup && cache.SudoListsRule, "the client's cache no longer holds ann's authorization without a refresh: %+v (K20: a cache view is stale until sss_cache -E and a restart)", cache)
		a.pending(true)
	})

	d.arm("A7 external drift is repaired and the second run writes nothing", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		if err := lv.ipaDo(
			freeiparpc.Command{Method: "user_mod", Args: []any{"p26-ann"}, Options: map[string]any{"givenname": "Drifted"}},
			freeiparpc.Command{Method: "group_add_member", Args: []any{"team-p26"}, Options: map[string]any{"user": []any{"p26-eve"}}},
			freeiparpc.Command{Method: "user_disable", Args: []any{"p26-cat"}},
		); err != nil {
			a.fail("the drift: %v", err)
			return
		}
		ws := lv.copyWorkspace(base(), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.update p26-ann", "group.member_user.remove team-p26", "user.enable p26-cat")
		a.verifyClean(r)
		again := a.apply(ws)
		a.exit(again, 4)
		a.ok(again.HasDoc && len(again.Doc.Plan1.Operations) == 0 && again.WriteN == 0, "the rerun wrote: %v", again.Writes)
	})

	d.runA8(base, oneUser)
	d.runA9(base, oneUser)
	d.runA10(base)
	d.runA11A12A13(base)
	d.runA14(base)
	d.runA15(base)
	d.runA17(oneUser)
	d.runA18(oneUser)
	d.runA19(base)
	d.runA20(base)
	d.runA21(base)
	d.runA22(base)
}

// runA1 makes the baseline: the roster applied by the Ansible engine and acknowledged, the Go
// preview and apply of it find nothing to do, and both VMs are snapshotted.
func (d *applyDriver) runA1() {
	lv := d.lv
	d.arm("A1 baseline", func(a *armCtx) {
		if err := lv.rollback(lv.baseTag); err != nil {
			a.fail("rollback to the enrolled snapshot: %v", err)
			return
		}
		ws := lv.copyWorkspace(d.baseRoster("admin"), "", nil)
		if !a.legacy(ws) {
			return
		}
		// Test set-up through the admin: the two logins of the self-lockout arms reach admins, and no
		// password is on the first-login-must-change flag, so a password login works.
		setup := "ipa group-add-member admins --users=p26-adm >/dev/null && ipa group-add-member admins --groups=role-p26-ops >/dev/null"
		for _, u := range []string{"p26-ann", "p26-ben", "p26-cat", "p26-dan", "p26-eve", "p26-adm", "p26-adn"} {
			setup += " && ipa user-mod " + u + " --setattr krbPasswordExpiration=20371231000000Z >/dev/null"
		}
		if out, err := lv.ipaCLI(setup); err != nil {
			a.fail("the set-up through the admin: %v\n%s", err, tail(out, 600))
			return
		}
		pr, doc, ok := a.preview(ws)
		a.ok(pr.ExitCode == 0 && ok && len(doc.Operations) == 0 && doc.Stats.Writes == 0, "the preview of the baseline: exit %d, operations %v\n%s", pr.ExitCode, opLines(doc.Plan), tail(pr.Out, 800))
		r := a.apply(ws)
		a.exit(r, 0)
		if r.HasDoc {
			a.ok(!r.Doc.Entry.Ran && r.Doc.Entry.Pending != nil && !*r.Doc.Entry.Pending, "the baseline apply: %+v", r.Doc.Authorization)
		}
		a.ok(r.WriteN == 0, "the baseline apply wrote: %v", r.Writes)
		if !a.pending(false) {
			return
		}
		d.ackedTag = "p26-acked"
		if err := lv.snapshot(d.ackedTag); err != nil {
			a.fail("snapshot: %v", err)
			d.ackedTag = ""
			return
		}
		if len(a.fails) != 0 {
			d.ackedTag = ""
		}
	})
}

func (d *applyDriver) runA8(base func() rosterDoc, oneUser func(string, ...func(map[string]any)) rosterDoc) {
	lv := d.lv
	d.arm("A8(i) a password the policy refuses", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		// Test set-up: a history policy on team-p26, and ben's password set once under it, so the same
		// password again is a reuse; its expiry moved out so the plan chooses a reset (the user is not
		// on a password an administrator set last).
		pw := d.pw("p26-ben")
		// The password goes to the server through the Phase 0 client, not through a command line.
		if out, err := lv.ipaCLI("ipa pwpolicy-add team-p26 --priority=1 --history=3 >/dev/null"); err != nil {
			a.fail("set-up (policy): %v\n%s", err, tail(out, 400))
			return
		}
		if err := lv.ipaDo(freeiparpc.Command{Method: "passwd", Args: []any{"p26-ben"}, Options: map[string]any{"password": pw}}); err != nil {
			a.fail("set-up (password): %v", err)
			return
		}
		if out, err := lv.ipaCLI("ipa user-mod p26-ben --setattr krbPasswordExpiration=20371231000000Z >/dev/null"); err != nil {
			a.fail("set-up (expiry): %v\n%s", err, tail(out, 400))
			return
		}
		roster := d.mutate(base(), func(r rosterDoc) {
			find(r, "users", "p26-ben")["password"] = map[string]any{"initial": pw, "preserve_existing": false}
			setMembers(r, "team-p26", "p26-ann", "p26-ben", "p26-dan") // cat is removed: S5, after the password
		})
		ws := lv.copyWorkspace(roster, "", nil)
		r := a.apply(ws)
		a.exit(r, 1)
		a.opsAre(r, "group.member_user.remove team-p26", "user.password.reset p26-ben")
		if r.HasDoc {
			a.ok(a.outcome(r, "user.password.reset:p26-ben") == OutcomeFailed, "the reset is %q, want failed", a.outcome(r, "user.password.reset:p26-ben"))
			a.ok(a.outcome(r, "group.member_user.remove:team-p26") == OutcomeNotExecuted, "the member removal is %q, want not_executed", a.outcome(r, "group.member_user.remove:team-p26"))
			a.fact("verdict", r.Doc.Verdict)
		}
		a.writesAre(r, map[string]int{"passwd": 1})
		a.ok(strings.Contains(a.serverHas("ipa group-show team-p26"), "p26-cat"), "cat was removed although the stage before it failed")
		// Fixed: another password, and the run converges.
		fixed := d.mutate(roster, func(r rosterDoc) {
			find(r, "users", "p26-ben")["password"] = map[string]any{"initial": randomPassword(), "preserve_existing": false}
		})
		lv.setRoster(ws, fixed)
		r2 := a.apply(ws)
		a.exit(r2, 4)
		a.opsAre(r2, "group.member_user.remove team-p26", "user.password.reset p26-ben")
		a.verifyClean(r2)
	})

	d.arm("A8(ii) the tunnel is killed with a write sent and its answer unread", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-n8"), "", nil)
		logAt, _ := serverLogSize(lv.srv)
		p := lv.startPilot(a.data, a.applyArgs(ws, filepath.Join(lv.tmp, "a8.json")), "after_send:S3:1")
		n, err := p.waitNotify("after_send:S3:1", hookWait)
		if err != nil {
			a.fail("%v", err)
			return
		}
		a.ok(a.waitWrite("user_add", logAt, 60*time.Second), "the server did not log the user_add")
		a.killChild(p, `-W`)
		p.answer(n, "drop")
		res, err := p.wait(5 * time.Minute)
		if err != nil {
			a.fail("%v", err)
			return
		}
		r := a.collect(res, filepath.Join(lv.tmp, "a8.json"), logAt)
		// The write had been applied: unknown, resolved by the read after the writes as converged. The
		// stage after it did not run (S3 stopped the run), so the password the plan still owes is a
		// remaining operation on an object the run changed: the run is partial_failed, exit 1 (spec §10.2).
		a.exit(r, 1)
		if r.HasDoc {
			o := a.opOf(r, "user.create:p26-n8")
			a.ok(o.Outcome == OutcomeUnknown && o.Resolution == resolutionConverged, "user.create: %+v, want unknown resolved converged", o)
			a.fact("operation", map[string]any{"outcome": o.Outcome, "resolution": o.Resolution, "error": o.Error})
			a.ok(a.outcome(r, "user.password.initialize:p26-n8") == OutcomeNotExecuted, "the stage after it is %q, want not_executed", a.outcome(r, "user.password.initialize:p26-n8"))
			a.ok(r.Doc.Verify.Done && !r.Doc.Verify.OK() && len(r.Doc.Verify.Remaining) == 1, "the read after the writes: %+v", r.Doc.Verify)
			a.ok(r.Doc.Outcome == "partial_failed", "the run's outcome is %q, want partial_failed", r.Doc.Outcome)
			a.fact("run", map[string]any{"outcome": r.Doc.Outcome, "failed_step": r.Doc.FailedStep, "verdict": r.Doc.Verdict})
		}
		// The rerun converges and does not create the user a second time: the one write is the password.
		again := a.apply(ws)
		a.exit(again, 4)
		a.opsAre(again, "user.password.initialize p26-n8")
		a.writesAre(again, map[string]int{"passwd": 1})
		a.verifyClean(again)
	})
}

func (a *armCtx) applyArgs(ws, result string, extra ...string) []string {
	return append([]string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "users-groups", "--result-out", result, "--timeout", "10m"}, extra...)
}

func (a *armCtx) opOf(r applyRun, id string) OpResult {
	for _, o := range r.Doc.Ops {
		if o.Operation.ID == id {
			return o
		}
	}
	return OpResult{}
}

func (d *applyDriver) runA9(base func() rosterDoc, oneUser func(string, ...func(map[string]any)) rosterDoc) {
	lv := d.lv
	for _, wait := range []string{"0", "30m"} {
		wait := wait
		d.arm("A9 a busy lock, --lock-wait "+wait, func(a *armCtx) {
			if !a.fresh() {
				return
			}
			wsL := lv.copyWorkspace(base(), "", nil)
			wsG := lv.copyWorkspace(oneUser("p26-wait"), "", nil)
			legacyDone := make(chan pilotResult, 1)
			go func() {
				legacyDone <- lv.runPilot(lv.pilot, filepath.Join(lv.tmp, "data-legacy-"+wait), []string{"reconcile", "--dir", wsL, "--component", "freeipa-identity", "--force"})
			}()
			end := time.Now().Add(2 * time.Minute)
			for !a.lockHeld() && time.Now().Before(end) {
				time.Sleep(time.Second)
			}
			if !a.ok(a.lockHeld(), "the legacy run never took the lock") {
				<-legacyDone
				return
			}
			logins := a.loginCount()
			start := time.Now()
			if wait == "0" {
				r := a.apply(wsG, "--lock-wait", "0")
				a.exit(r, 1)
				a.ok(strings.Contains(r.Out, "沒有取得鎖，沒有任何寫入"), "the refusal does not say nothing was written:\n%s", tail(r.Out, 600))
				a.ok(time.Since(start) < 90*time.Second, "--lock-wait 0 took %s", time.Since(start))
				a.ok(a.loginCount() == logins, "the run logged in to FreeIPA with the lock busy")
				a.ok(!r.HasDoc, "a result file exists for a run that did not start")
				<-legacyDone
				return
			}
			var waited float64
			resCh := make(chan applyRun, 1)
			go func() { resCh <- a.apply(wsG, "--lock-wait", "30m") }()
			var r applyRun
			select {
			case r = <-resCh:
				a.fail("the run ended before the legacy run gave the lock back:\n%s", tail(r.Out, 800))
				<-legacyDone
				return
			case <-time.After(20 * time.Second):
			}
			a.ok(a.loginCount() == logins, "the waiting run logged in while the lock was busy")
			lres := <-legacyDone
			a.ok(lres.ExitCode == 0, "the legacy run exited %d", lres.ExitCode)
			r = <-resCh
			waited = time.Since(start).Seconds()
			a.exit(r, 4)
			a.ok(waited > 20, "the waiting run did not wait (%.0fs)", waited)
			a.ok(strings.Contains(r.Out, "等待 FreeIPA server"), "no progress line while waiting:\n%s", tail(r.Out, 500))
			a.fact("waited_seconds", int(waited))
			a.opsAre(r, "user.create p26-wait", "user.password.initialize p26-wait")
			a.pending(true)
		})
	}
}

func (d *applyDriver) runA10(base func() rosterDoc) {
	lv := d.lv
	d.arm("A10 the lock is lost with a write in flight", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.mutate(base(), func(r rosterDoc) {
			d.addUser(r, d.user("p26-x1", noPassword))
			d.addGroup(r, group("team-p26x", "team", []string{"p26-x1"}, nil))
		})
		ws := lv.copyWorkspace(roster, "", nil)
		recv := newReceiver()
		defer recv.srv.Close()
		d.webhookFor(ws, recv)
		result := filepath.Join(lv.tmp, "a10.json")
		logAt, _ := serverLogSize(lv.srv)
		p := lv.startPilot(a.data, a.applyArgs(ws, result), "after_send:S3:1")
		n, err := p.waitNotify("after_send:S3:1", hookWait)
		if err != nil {
			a.fail("%v", err)
			return
		}
		a.ok(a.waitWrite("user_add", logAt, 60*time.Second), "the server did not log the user_add")
		if !a.killChild(p, `flock`) {
			return
		}
		time.Sleep(1500 * time.Millisecond) // the lock's session has ended and pilot has seen it
		p.answer(n, "resume")
		res, err := p.wait(5 * time.Minute)
		if err != nil {
			a.fail("%v", err)
			return
		}
		r := a.collect(res, result, logAt)
		a.exit(r, 1)
		if r.HasDoc {
			a.ok(r.Doc.Outcome == "partial_failed" && r.Doc.FailedStep == "apply", "outcome %s at %q, want partial_failed at apply", r.Doc.Outcome, r.Doc.FailedStep)
			a.ok(a.outcome(r, "user.create:p26-x1") == OutcomeSuccess, "the in-flight write is %q: it must be its real answer, success", a.outcome(r, "user.create:p26-x1"))
			a.ok(a.outcome(r, "group.member_user.add:team-p26x") == OutcomeNotExecuted, "the next stage's write is %q, want not_executed", a.outcome(r, "group.member_user.add:team-p26x"))
			a.ok(r.Doc.Verify.Done, "the read after the writes was not attempted")
		}
		a.ok(r.Writes["group_add_member"] == 0, "a write was sent after the lock was lost: %v", r.Writes)
		cls := a.failureClass(recv)
		a.ok(cls == "apply_failed", "the outbox event's failure class is %q, want apply_failed", cls)
		a.ok(a.lockFree(30*time.Second), "the lock is not free after the run")
	})
}

func (d *applyDriver) runA11A12A13(base func() rosterDoc) {
	lv := d.lv
	d.arm("A11 a docker-connection workspace", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.user("p26-d11")) }), "", nil)
		hosts := filepath.Join(ws, "hosts.yml")
		data, _ := os.ReadFile(hosts)
		patched := strings.Replace(string(data), "  ipa1:\n", "  ipa1:\n    ansible_connection: docker\n", 1)
		if patched == string(data) {
			a.fail("hosts.yml has no ipa1 host to patch")
			return
		}
		_ = os.WriteFile(hosts, []byte(patched), 0o600)
		if err := lv.regenerateInventory(ws); err != nil {
			a.fail("%v", err)
			return
		}
		before := a.sshAccepted()
		r := a.applyLocal(ws)
		others := a.sshOthersSince(before)
		a.exit(r, 1)
		a.ok(strings.Contains(r.Out, "ansible_connection") || strings.Contains(r.Out, "SSH 連線設定"), "the refusal does not name the connection variable:\n%s", tail(r.Out, 500))
		a.ok(others == 0, "%d ssh sessions to the server were opened by the run", others)
		a.ok(!r.HasDoc, "a result file exists for a run that never connected")
	})
	d.arm("A12 a uid change", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		before := lv.journal()
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { find(r, "users", "p26-ann")["uid"] = 1927609999 }), "", nil)
		r := a.apply(ws)
		a.exit(r, 3)
		a.ok(r.HasDoc && r.Doc.Verdict == VerdictBlocked && len(r.Doc.Plan1.Blocked) > 0 && r.Doc.Plan1.Blocked[0].Reason == BlockedIDChange, "the result: %+v", r.Doc.Plan1.Blocked)
		a.ok(r.HasDoc && !r.Doc.Entry.Ran && r.WriteN == 0, "the entry ran or a write was sent: %v", r.Writes)
		a.ok(lv.journal() == before, "the journal changed: %+v -> %+v", before, lv.journal())
	})
	d.arm("A13 a journal whose domain is not the inventory's", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		before := lv.journal()
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.user("p26-d13")) }), "", map[string]string{"freeipa_domain": "other.example"})
		r := a.apply(ws)
		a.exit(r, 1)
		a.ok(r.HasDoc && !r.Doc.Entry.Ran && r.Doc.Stop != nil && r.Doc.Stop.Stage == stopEntry && r.WriteN == 0, "the result: entry %+v stop %+v writes %v\n%s", r.Doc.Entry, r.Doc.Stop, r.Writes, tail(r.Out, 900))
		a.ok(lv.journal() == before, "the journal changed: %+v -> %+v", before, lv.journal())
	})
}

// ---- A14: the engine does not take its own login away ----

func (d *applyDriver) runA14(base func() rosterDoc) {
	lv := d.lv
	type row struct {
		name      string
		principal string
		mutate    func(r rosterDoc)
		setup     string
		exit      int
		want      string // a text of the refusal
	}
	adm := func(r rosterDoc) map[string]any { return find(r, "users", "p26-adm") }
	rows := []row{
		{"(a) the login is disabled", "p26-adm", func(r rosterDoc) { adm(r)["state"] = "disabled" }, "", 3, "protected_object"},
		{"(b) the login is deleted", "p26-adm", func(r rosterDoc) { adm(r)["state"] = "absent" }, "", 3, "protected_object"},
		// (c) cannot be put to the engine through a roster: the roster validator refuses a group named
		// admins (a role group must be called role-*), so the login's own place in admins is not
		// something a roster can change. The row records that refusal; the boundary itself is the unit table's.
		{"(c) a roster cannot name admins", "p26-adm", func(r rosterDoc) {
			d.addGroup(r, group("admins", "role", nil, []string{"role-p26-ops"}))
		}, "", 1, "group category prefix"},
		{"(d) the only path through a nested group is cut", "p26-adn", func(r rosterDoc) { setMembers(r, "role-p26-old") }, "", 3, "protected_object"},
		{"(e) its own password is reset", "p26-adm", func(r rosterDoc) {
			adm(r)["password"] = map[string]any{"initial": d.pw("p26-adm"), "preserve_existing": false}
		}, "", 3, "protected_object"},
		{"(f) the path is built in the same plan", "p26-adn", func(r rosterDoc) {
			d.addGroup(r, group("role-p26-new", "role", []string{"p26-adn"}, nil))
			setMembers(r, "role-p26-old")
			find(r, "groups", "role-p26-ops")["membership"].(map[string]any)["groups"] = []string{"role-p26-old", "role-p26-new"}
		}, "", 3, "S5"},
		// The controls: what the rule must let through.
		{"control: another admin is disabled", "p26-adm", func(r rosterDoc) { find(r, "users", "p26-adn")["state"] = "disabled" }, "", 4, ""},
		{"control (f): the path already exists", "p26-adn", func(r rosterDoc) {
			d.addGroup(r, group("role-p26-new", "role", []string{"p26-adn"}, nil))
			setMembers(r, "role-p26-old")
			ops := find(r, "groups", "role-p26-ops")["membership"].(map[string]any)
			ops["groups"] = []string{"role-p26-old", "role-p26-new"}
			ops["users"] = []string{"p26-adn"}
		}, "ipa group-add-member role-p26-ops --users=p26-adn >/dev/null", 4, ""},
	}
	for _, rw := range rows {
		rw := rw
		d.arm("A14 "+rw.name, func(a *armCtx) {
			if !a.fresh() {
				return
			}
			if rw.setup != "" {
				if out, err := lv.ipaCLI(rw.setup); err != nil {
					a.fail("set-up: %v\n%s", err, tail(out, 300))
					return
				}
			}
			ws := lv.copyWorkspace(d.mutate(d.baseRoster(rw.principal), rw.mutate), d.pw(rw.principal), nil)
			before := lv.journal()
			r := a.apply(ws)
			a.exit(r, rw.exit)
			switch rw.exit {
			case 3:
				a.ok(r.HasDoc && r.Doc.Verdict == VerdictBlocked && !r.Doc.Entry.Ran && r.WriteN == 0, "the run was not a zero-write refusal without the entry: %+v %v", r.Doc.Authorization, r.Writes)
				a.ok(strings.Contains(r.Out, rw.want), "the refusal does not hold %q:\n%s", rw.want, tail(r.Out, 800))
				a.ok(lv.journal() == before, "the journal changed")
			case 1:
				a.ok(!r.HasDoc && r.WriteN == 0 && strings.Contains(r.Out, rw.want), "the roster was not refused with %q before any plan:\n%s", rw.want, tail(r.Out, 600))
				a.ok(lv.journal() == before, "the journal changed")
			default:
				a.ok(r.HasDoc && r.Doc.Verdict == VerdictUnsettled && r.Doc.Entry.Ran && r.WriteN > 0, "the control did not run: %+v %v", r.Doc.Authorization, r.Writes)
			}
		})
	}
}

// ---- A15: a password the engine cannot hand out ----

func (d *applyDriver) runA15(base func() rosterDoc) {
	lv := d.lv
	vault := func(a *armCtx) string {
		cmd := fmt.Sprintf("ANSIBLE_VAULT_PASSWORD_FILE=%s ansible-vault encrypt_string 'x' 2>/dev/null", lv.vaultPass)
		out, err := execShell(cmd)
		if err != nil || !strings.Contains(out, "$ANSIBLE_VAULT") {
			a.fail("ansible-vault encrypt_string: %v", err)
			return ""
		}
		return out
	}
	type row struct {
		name  string
		value string // the YAML text of password.initial
		exit  int
		want  string
		ssh   bool // whether a tunnel may have been made
	}
	for _, rw := range []row{
		{"a template", `"{{ lookup('env', 'HOME') }}"`, 3, "password_value_unsupported", true},
		{"an inline !vault", "__VAULT__", 3, "password_value_unsupported", true},
		{"a plain string (the control)", `"` + d.pw("p26-plain") + `"`, 4, "", true},
		{"an unquoted number", "12345678", 1, "quote the password", false},
	} {
		rw := rw
		d.arm("A15 "+rw.name, func(a *armCtx) {
			if !a.fresh() {
				return
			}
			roster := d.mutate(base(), func(r rosterDoc) {
				d.addUser(r, d.user("p26-pwt", func(m map[string]any) { m["password"] = map[string]any{"initial": "__INITIAL__"} }))
			})
			ws := lv.copyWorkspace(roster, "", nil)
			path := filepath.Join(ws, ".vault", "ipa-identity.yaml")
			data, _ := os.ReadFile(path)
			text := string(data)
			val := rw.value
			if val == "__VAULT__" {
				enc := vault(a)
				if enc == "" {
					return
				}
				var b strings.Builder
				b.WriteString("!vault |\n")
				for _, l := range strings.Split(strings.TrimRight(enc, "\n"), "\n")[1:] {
					b.WriteString("          " + strings.TrimSpace(l) + "\n")
				}
				val = strings.TrimRight(b.String(), "\n")
			}
			text = strings.Replace(text, "initial: __INITIAL__", "initial: "+val, 1)
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				a.fail("%v", err)
				return
			}
			logins := a.loginCount() // its own ssh connection is made before the count that the run is compared with
			before := a.sshAccepted()
			var r applyRun
			if rw.ssh {
				r = a.apply(ws)
			} else {
				r = a.applyLocal(ws)
			}
			a.exit(r, rw.exit)
			if rw.want != "" {
				a.ok(strings.Contains(r.Out, rw.want), "the refusal does not hold %q:\n%s", rw.want, tail(r.Out, 700))
			}
			if rw.exit == 3 {
				a.ok(r.HasDoc && !r.Doc.Entry.Ran && r.WriteN == 0, "the run entered or wrote: %v", r.Writes)
			}
			if !rw.ssh {
				a.ok(a.sshOthersSince(before) == 0 && a.loginCount() == logins, "a tunnel or a login was made for a roster the adapter refuses")
			}
		})
	}
}

// ---- A17: a signal or the timeout with a write in flight ----

func (d *applyDriver) runA17(oneUser func(string, ...func(map[string]any)) rosterDoc) {
	lv := d.lv
	for _, mode := range []string{"SIGINT", "--timeout"} {
		mode := mode
		d.arm("A17("+map[string]string{"SIGINT": "i", "--timeout": "ii"}[mode]+") "+mode+" with a write in flight", func(a *armCtx) {
			if !a.fresh() {
				return
			}
			ws := lv.copyWorkspace(oneUser("p26-n17"), "", nil)
			recv := newReceiver()
			defer recv.srv.Close()
			d.webhookFor(ws, recv)
			result := filepath.Join(lv.tmp, "a17-"+strings.TrimLeft(mode, "-")+".json")
			logAt, _ := serverLogSize(lv.srv)
			extra := []string{}
			if mode == "--timeout" {
				extra = []string{"--timeout", "75s"}
			}
			p := lv.startPilot(a.data, a.applyArgs(ws, result, extra...), "after_send:S3:1")
			if _, err := p.waitNotify("after_send:S3:1", hookWait); err != nil {
				a.fail("%v", err)
				return
			}
			a.ok(a.waitWrite("user_add", logAt, 60*time.Second), "the server did not log the user_add")
			if mode == "SIGINT" {
				p.signal(syscall.SIGINT)
			}
			res, err := p.wait(5 * time.Minute)
			if err != nil {
				a.fail("%v", err)
				return
			}
			r := a.collect(res, result, logAt)
			a.exit(r, 1) // partial_failed: an operation the run sent is unknown
			if r.HasDoc {
				o := a.opOf(r, "user.create:p26-n17")
				a.ok(o.Outcome == OutcomeUnknown, "the in-flight write is %q, want unknown", o.Outcome)
				a.ok(r.Doc.Outcome == "partial_failed", "the run's outcome is %q, want partial_failed (not evidence_failed)", r.Doc.Outcome)
				a.ok(r.Doc.Verify.Done, "the read after the writes was not attempted")
				a.fact("exit", r.ExitCode)
				a.fact("operation", map[string]any{"outcome": o.Outcome, "resolution": o.Resolution})
				a.fact("run", map[string]any{"outcome": r.Doc.Outcome, "failed_step": r.Doc.FailedStep, "verdict": r.Doc.Verdict})
			} else {
				a.fail("no result file")
			}
			cls := a.failureClass(recv)
			a.ok(cls != "", "no failure event reached the receiver")
			a.fact("failure_class", cls)
			a.ok(a.lockFree(30*time.Second), "the lock is not free after the run")
			a.ok(r.WriteN == 1, "the server logged %d writes: %v", r.WriteN, r.Writes)
		})
	}
	d.arm("A17 a second Ctrl-C ends pilot at once", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(oneUser("p26-n17b"), "", nil)
		p := lv.startPilot(a.data, a.applyArgs(ws, filepath.Join(lv.tmp, "a17b.json")), "after_send:S3:1")
		if _, err := p.waitNotify("after_send:S3:1", hookWait); err != nil {
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
}

// ---- A18: the entry is the obligation, whatever happens next ----

func (d *applyDriver) runA18(oneUser func(string, ...func(map[string]any)) rosterDoc) {
	lv := d.lv
	var killTag string
	var rosterWS string
	d.arm("A18 pilot is killed after the entry", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		a.ok(!lv.journal().Pending, "the journal is not acked before the run")
		rosterWS = lv.copyWorkspace(oneUser("p26-n18"), "", nil)
		logAt, _ := serverLogSize(lv.srv)
		p := lv.startPilot(a.data, a.applyArgs(rosterWS, filepath.Join(lv.tmp, "a18.json")), "after_entry")
		if _, err := p.waitNotify("after_entry", hookWait); err != nil {
			a.fail("%v", err)
			return
		}
		a.ok(lv.journal().Pending, "the journal is not owed at after_entry: the entry did not record the obligation")
		w, _ := lv.writesSince(logAt)
		a.ok(len(w) == 0, "writes were logged before the first write: %v", w)
		p.kill()
		_, _ = p.wait(30 * time.Second)
		a.ok(a.lockFree(60*time.Second), "the lock is not free after the kill")
		w, _ = lv.writesSince(logAt)
		a.ok(len(w) == 0, "writes were logged after the kill: %v", w)
		killTag = "p26-killed"
		if err := lv.snapshot(killTag); err != nil {
			a.fail("snapshot: %v", err)
			killTag = ""
		}
	})
	if killTag == "" {
		return
	}
	defer lv.deleteSnapshot(killTag)
	d.arm("A18(i) the roster is back to zero difference", func(a *armCtx) {
		if err := lv.rollback(killTag); err != nil {
			a.fail("rollback: %v", err)
			return
		}
		a.ok(lv.journal().Pending, "the journal is not owed at the start")
		ws := lv.copyWorkspace(d.baseRoster("admin"), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.ok(r.HasDoc && !r.Doc.Entry.Ran && r.Doc.Authorization.Source == ObligationPreviousRun && r.WriteN == 0, "the run: %+v writes %v", r.Doc.Authorization, r.Writes)
	})
	d.arm("A18(ii) the original roster again", func(a *armCtx) {
		if err := lv.rollback(killTag); err != nil {
			a.fail("rollback: %v", err)
			return
		}
		r := a.apply(rosterWS)
		a.exit(r, 4)
		a.ok(r.HasDoc && r.Doc.Entry.Ran && r.Doc.Authorization.Source == ObligationThisRun, "the entry did not run again: %+v", r.Doc.Authorization)
		a.opsAre(r, "user.create p26-n18", "user.password.initialize p26-n18")
	})
}
