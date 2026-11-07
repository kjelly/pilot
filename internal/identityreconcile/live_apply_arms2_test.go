package identityreconcile

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

func execShell(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).Output()
	return string(out), err
}

// stopped runs the Go apply of ws with a stop at point, runs inject while it is stopped (an external
// writer), lets it go on, and returns what it left.
func (a *armCtx) stopped(ws, point string, inject func()) applyRun {
	result := filepath.Join(a.lv.tmp, fmt.Sprintf("stopped-%d.json", time.Now().UnixNano()))
	logAt, _ := serverLogSize(a.lv.srv)
	p := a.lv.startPilot(a.data, a.applyArgs(ws, result), point)
	n, err := p.waitNotify(point, hookWait)
	if err != nil {
		a.fail("%v", err)
		p.kill()
		return applyRun{}
	}
	inject()
	p.answer(n, "resume")
	res, err := p.wait(8 * time.Minute)
	if err != nil {
		a.fail("%v", err)
		return applyRun{}
	}
	return a.collect(res, result, logAt)
}

// ---- A19: an external writer between the plan and the write ----

func (d *applyDriver) runA19(base func() rosterDoc) {
	lv := d.lv
	ipaOrFail := func(a *armCtx, cmd string) {
		if out, err := lv.ipaCLI(cmd); err != nil {
			a.fail("the external writer: %v\n%s", err, tail(out, 300))
		}
	}
	teamHas := func(a *armCtx, user string) bool {
		return strings.Contains(a.serverHas("ipa group-show team-p26"), user)
	}
	userExists := func(a *armCtx, user string) bool {
		return !strings.Contains(a.serverHas("ipa user-show "+user+" 2>&1"), "not found")
	}

	// (a) before S4: the password a plan initializes was set by someone else.
	pwx := func() rosterDoc {
		return d.mutate(base(), func(r rosterDoc) {
			d.addUser(r, d.user("p26-pwx"))
			setMembers(r, "team-p26", "p26-ann", "p26-ben", "p26-dan")
		})
	}
	d.arm("A19(a) the password was set before S4", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(pwx(), "", nil)
		r := a.stopped(ws, "before_stage:S4", func() {
			// Someone else sets the password the plan means to initialize: through the Phase 0 client,
			// with a generated value, not through a command line.
			if err := lv.ipaDo(freeiparpc.Command{Method: "passwd", Args: []any{"p26-pwx"}, Options: map[string]any{"password": d.pw("p26-external")}}); err != nil {
				a.fail("the external writer: %v", err)
			}
		})
		a.exit(r, 1)
		a.ok(r.HasDoc && a.outcome(r, "user.password.initialize:p26-pwx") == OutcomeConflictFailed, "the password operation is %q, want conflict-failed", a.outcome(r, "user.password.initialize:p26-pwx"))
		a.ok(r.HasDoc && a.outcome(r, "group.member_user.remove:team-p26") == OutcomeNotExecuted, "the stage after it is %q, want not_executed", a.outcome(r, "group.member_user.remove:team-p26"))
		a.ok(r.Writes["passwd"] == 1, "passwd was logged %d times: only the external one is expected", r.Writes["passwd"])
		a.ok(teamHas(a, "p26-cat"), "cat was removed although S4 stopped the run")
	})
	d.arm("A19(a) control: nothing is injected", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.apply(lv.copyWorkspace(pwx(), "", nil))
		a.exit(r, 4)
		a.ok(r.Writes["passwd"] == 1 && !teamHas(a, "p26-cat"), "the control did not complete: %v", r.Writes)
	})

	// (b) before S5: the authoritative group gained a direct member the roster does not name.
	revoke := func() rosterDoc {
		return d.mutate(base(), func(r rosterDoc) {
			setMembers(r, "team-p26", "p26-ann", "p26-ben", "p26-dan")
			find(r, "users", "p26-ben")["state"] = "disabled" // S7: a later stage that must not run
		})
	}
	d.arm("A19(b) a member was added before S5", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.stopped(lv.copyWorkspace(revoke(), "", nil), "before_stage:S5", func() {
			ipaOrFail(a, "ipa group-add-member team-p26 --users=p26-eve >/dev/null")
		})
		a.exit(r, 1)
		a.ok(teamHas(a, "p26-cat") && teamHas(a, "p26-eve"), "a member was revoked although the group had changed since the plan")
		a.ok(!strings.Contains(a.serverHas("ipa user-show p26-ben"), "Account disabled: True"), "ben was disabled although S5 stopped the run")
		a.ok(r.HasDoc && a.outcome(r, "user.disable:p26-ben") == OutcomeNotExecuted, "the disable is %q", a.outcome(r, "user.disable:p26-ben"))
	})
	d.arm("A19(b) control: nothing is injected", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.apply(lv.copyWorkspace(revoke(), "", nil))
		a.exit(r, 4)
		a.ok(!teamHas(a, "p26-cat") && strings.Contains(a.serverHas("ipa user-show p26-ben"), "Account disabled: True"), "the control did not complete")
	})

	// (c) before S7: a user the plan disables was disabled already, or was deleted and made again.
	disableBen := func() rosterDoc {
		return d.mutate(base(), func(r rosterDoc) {
			find(r, "users", "p26-ben")["state"] = "disabled"
			find(r, "users", "p26-dan")["state"] = "absent"
			setMembers(r, "team-p26", "p26-ann", "p26-ben", "p26-cat") // an absent user is no member (S5 removes dan first)
		})
	}
	d.arm("A19(c) the user was disabled by someone else before S7", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.stopped(lv.copyWorkspace(disableBen(), "", nil), "before_stage:S7", func() { ipaOrFail(a, "ipa user-disable p26-ben >/dev/null") })
		a.exit(r, 4)
		a.ok(r.HasDoc && a.outcome(r, "user.disable:p26-ben") == OutcomeNoop, "the disable is %q, want noop, not a conflict", a.outcome(r, "user.disable:p26-ben"))
		a.ok(!userExists(a, "p26-dan"), "the next stage did not run: dan is still there")
	})
	d.arm("A19(c) the user was deleted and made again before S7", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.stopped(lv.copyWorkspace(disableBen(), "", nil), "before_stage:S7", func() {
			ipaOrFail(a, "ipa user-del p26-ben >/dev/null && ipa user-add p26-ben --first=P26 --last=ben >/dev/null")
		})
		a.exit(r, 1)
		a.ok(r.HasDoc && a.outcome(r, "user.disable:p26-ben") == OutcomeConflictFailed, "the disable is %q, want conflict-failed", a.outcome(r, "user.disable:p26-ben"))
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-ben"), "Account disabled: False"), "the new ben was disabled")
		a.ok(userExists(a, "p26-dan"), "S8 ran although S7 stopped the run: dan is gone")
	})

	// (d) before S8: a user to delete was deleted and made again, with another one in the same batch.
	deletes := func() rosterDoc {
		return d.mutate(base(), func(r rosterDoc) {
			find(r, "users", "p26-dan")["state"] = "absent"
			find(r, "users", "p26-eve")["state"] = "absent"
			find(r, "groups", "data-p26")["state"] = "absent"
			setMembers(r, "team-p26", "p26-ann", "p26-ben", "p26-cat") // an absent user is no member
		})
	}
	d.arm("A19(d) a user to delete was made again before S8", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.stopped(lv.copyWorkspace(deletes(), "", nil), "before_stage:S8", func() {
			ipaOrFail(a, "ipa user-del p26-dan >/dev/null && ipa user-add p26-dan --first=P26 --last=dan >/dev/null")
		})
		a.exit(r, 1)
		a.ok(userExists(a, "p26-eve"), "eve was deleted although the batch had a user that was not the one planned for")
		a.ok(strings.Contains(a.serverHas("ipa group-show data-p26 2>&1"), "Group name: data-p26"), "the group was deleted although S8 stopped")
		a.ok(r.HasDoc && a.outcome(r, "user.delete:p26-eve") == OutcomeNotExecuted && a.outcome(r, "group.delete:data-p26") == OutcomeNotExecuted,
			"eve %q, data-p26 %q: want not_executed for both", a.outcome(r, "user.delete:p26-eve"), a.outcome(r, "group.delete:data-p26"))
	})
	d.arm("A19(d) control: nothing is injected", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		r := a.apply(lv.copyWorkspace(deletes(), "", nil))
		a.exit(r, 4)
		a.ok(!userExists(a, "p26-dan") && !userExists(a, "p26-eve"), "the control did not delete")
	})

	// (e) after the entry: the second plan has a revocation the first one did not.
	d.arm("A19(e) a member was added after the entry, so Plan2 revokes more than Plan1", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.user("p26-n19e")) }), "", nil)
		r := a.stopped(ws, "after_entry", func() { ipaOrFail(a, "ipa group-add-member team-p26 --users=p26-eve >/dev/null") })
		a.exit(r, 1)
		a.ok(r.HasDoc && r.Doc.Entry.Ran && r.WriteN == 1 /* the external writer's own */ && len(r.Doc.Conflicts) > 0, "the result: entry %+v conflicts %v writes %v", r.Doc.Entry, r.Doc.Conflicts, r.Writes)
		a.ok(!userExists(a, "p26-n19e"), "the user was created although the plan the operator saw is not the plan the run found")
		a.pending(true)
	})
}

// ---- A20: the session fails in the middle of a run ----

func (d *applyDriver) runA20(base func() rosterDoc) {
	lv := d.lv
	d.arm("A20 the session is invalidated before the second batch of S3", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.mutate(base(), func(r rosterDoc) {
			for i := 0; i < 30; i++ {
				d.addUser(r, d.user(fmt.Sprintf("p26-m%02d", i), noPassword))
			}
		})
		ws := lv.copyWorkspace(roster, "", nil)
		var ended string
		r := a.stopped(ws, "before_batch:S3:2", func() {
			// The sessions of the server's web service live as credential caches the session cookie leads to.
			out, err := lv.onServer("ls /run/ipa/ccaches | wc -l; rm -f /run/ipa/ccaches/*; ls /run/ipa/ccaches | wc -l")
			ended = strings.Join(strings.Fields(out), " ")
			if err != nil {
				a.fail("invalidating the sessions: %v", err)
			}
		})
		a.fact("sessions_before_after_removal", ended)
		a.exit(r, 4)
		if r.HasDoc {
			a.ok(r.Doc.Stats.Relogins >= 1, "the client did not log in again (relogins %d): the session was not invalidated, or the 401 was not seen", r.Doc.Stats.Relogins)
			a.fact("relogins", r.Doc.Stats.Relogins)
			a.fact("batch_outcomes", r.Doc.Counts())
			a.verifyClean(r)
		}
		a.ok(r.Writes["user_add"] == 30, "user_add was logged %d times, want 30: no write repeated, none lost", r.Writes["user_add"])
	})
}

// ---- A21: the authority is taken away in the middle of a run ----

func (d *applyDriver) runA21(base func() rosterDoc) {
	lv := d.lv
	d.arm("A21 the login is taken out of admins before S3", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.mutate(d.baseRoster("p26-adm"), func(r rosterDoc) {
			d.addGroup(r, group("team-p26w", "team", nil, nil))
			d.addUser(r, d.user("p26-n21", noPassword))
		})
		ws := lv.copyWorkspace(roster, d.pw("p26-adm"), nil)
		r := a.stopped(ws, "before_stage:S3", func() {
			if err := lv.ipaDo(freeiparpc.Command{Method: "group_remove_member", Args: []any{"admins"}, Options: map[string]any{"user": []any{"p26-adm"}}}); err != nil {
				a.fail("taking the login out of admins: %v", err)
			}
		})
		a.exit(r, 1)
		if r.HasDoc {
			o := a.opOf(r, "user.create:p26-n21")
			a.ok(o.Outcome == OutcomeFailed && strings.Contains(o.Error+o.Detail, "ACIError"), "the write is %+v, want failed with an ACIError", o)
			a.ok(a.outcome(r, "group.create:team-p26w") == OutcomeSuccess, "the group created in S1 is %q", a.outcome(r, "group.create:team-p26w"))
			a.ok(r.Doc.Outcome == "partial_failed", "outcome %q, want partial_failed", r.Doc.Outcome)
			a.fact("read_after", r.Doc.Verify.ReadError != "")
		}
	})
	d.arm("A21 a login that is not in admins is refused before any read", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.baseRoster("p26-ann"), d.pw("p26-ann"), nil)
		r := a.apply(ws)
		a.exit(r, 1)
		a.ok(!r.HasDoc && r.WriteN == 0, "a plan or a write exists for a login that is not an admin")
		a.ok(strings.Contains(r.Out, "admins"), "the refusal does not say why:\n%s", tail(r.Out, 500))
	})
}

// ---- A22: a user created disabled ----

func (d *applyDriver) runA22(base func() rosterDoc) {
	lv := d.lv
	d.arm("A22 a user created disabled", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.user("p26-off", noPassword, with("state", "disabled"))) }), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.create p26-off", "user.disable p26-off")
		a.ok(r.HasDoc && a.outcome(r, "user.disable:p26-off") == OutcomeSuccess && a.outcome(r, "user.create:p26-off") == OutcomeSuccess, "the operations ended %+v", r.Doc.Counts())
		a.ok(strings.Contains(a.serverHas("ipa user-show p26-off"), "Account disabled: True"), "the user is not disabled on the server")
		a.verifyClean(r)
	})
	d.arm("A22 control: an existing user is disabled", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		ws := lv.copyWorkspace(d.mutate(base(), func(r rosterDoc) { find(r, "users", "p26-cat")["state"] = "disabled" }), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.disable p26-cat")
		a.ok(r.HasDoc && a.outcome(r, "user.disable:p26-cat") == OutcomeSuccess, "the disable is %q", a.outcome(r, "user.disable:p26-cat"))
	})
}
