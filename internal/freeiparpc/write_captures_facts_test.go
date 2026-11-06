package freeiparpc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// The facts of the P2-4 captures (see write_captures_test.go for how they are
// run and tampered with). Each is something the writer's design in
// docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md rests
// on, with the K row of §9 it belongs to.

// labRealm is the realm of the server the captures were taken from.
const labRealm = "IPA.PILOT.INTERNAL"

var (
	resultPath = []any{"result", "result"}
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func entryPath(attr string, rest ...any) []any {
	return append(slices.Clone(resultPath), append([]any{attr}, rest...)...)
}

func p24Facts() []captureFact {
	var all []captureFact
	for _, f := range []func() []captureFact{
		factsPasswd, factsUserDelete, factsGroupWrites, factsMarker, factsMembers,
		factsUserFields, factsBatches, factsReReads, factsEmptyValues,
	} {
		all = append(all, f()...)
	}
	return all
}

// resetStamps is krblastpwdchange and krbpasswordexpiration of a user entry.
func resetStamps(e map[string]any) (last, exp string, err error) {
	if last, err = stampOf(e, "krblastpwdchange"); err != nil {
		return
	}
	exp, err = stampOf(e, "krbpasswordexpiration")
	return
}

// K6
func factsPasswd() []captureFact {
	passwd := func(uid string) Command {
		return Command{Method: "passwd", Args: []any{uid}, Options: map[string]any{"password": "(one-time; never stored)"}}
	}
	policy := func(c *factCheck, s *captureSet, name, attrName string, want string) {
		e, err := s.entry(name)
		if c.noError(err) {
			c.that(slices.Equal(attr(e, attrName), []string{want}), "%s: %s = %v, want %s (the capture was not taken under this policy)", name, attrName, attr(e, attrName), want)
		}
	}
	return []captureFact{
		{
			id: "K6 passwd succeeds with result true and the principal, and the answer has no password in it",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				for _, name := range []string{"passwd-success", "passwd-success-again"} {
					res, _, err := s.call(t_, name, passwd("p24cap-pw"))
					if !c.noError(err) {
						continue
					}
					var keys map[string]json.RawMessage
					_ = json.Unmarshal(res, &keys)
					var r struct {
						Result  bool   `json:"result"`
						Value   string `json:"value"`
						Summary string `json:"summary"`
					}
					_ = json.Unmarshal(res, &r)
					c.that(len(keys) == 3 && keys["result"] != nil && keys["value"] != nil && keys["summary"] != nil, "%s: the result has the keys %v, want result, value and summary only", name, keysOf(keys))
					c.that(r.Result, "%s: result = false", name)
					c.that(r.Value == "p24cap-pw@"+labRealm, "%s: value = %q", name, r.Value)
					c.that(r.Summary == `Changed password for "p24cap-pw@`+labRealm+`"`, "%s: summary = %q", name, r.Summary)
				}
				return c.err()
			},
			probes: []probe{
				set("result false", "passwd-success", false, "result", "result"),
				add("a password field in the result", "passwd-success", "x", "result", "password"),
				set("another principal", "passwd-success", "someone@"+labRealm, "result", "value"),
				asError("an error instead", "passwd-success"),
				asError("an error on the second reset", "passwd-success-again"),
				set("another summary", "passwd-success-again", "Changed", "result", "summary"),
			},
		},
		{
			id: "K6 an admin reset sets the expiration to the change time, under the default policy (maxlife 90): initialize = no change time yet, reset = expiration <= change",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				policy(&c, s, "pwpolicy-show-global-at-capture", "krbmaxpwdlife", "90")
				before, err := s.entry("user-show-no-password")
				if !c.noError(err) {
					return c.err()
				}
				last, exp, err := resetStamps(before)
				c.noError(err)
				c.that(last == "" && exp == "", "a user with no password has krblastpwdchange=%q krbpasswordexpiration=%q", last, exp)
				c.that(before["has_password"] == false && before["has_keytab"] == false, "has_password/has_keytab of a new user = %v/%v", before["has_password"], before["has_keytab"])
				var firstLast string
				for i, name := range []string{"user-show-after-passwd", "user-show-after-passwd-again"} {
					e, err := s.entry(name)
					if !c.noError(err) {
						continue
					}
					last, exp, err := resetStamps(e)
					c.noError(err)
					c.that(last != "" && exp != "", "%s: krblastpwdchange=%q krbpasswordexpiration=%q, want both set", name, last, exp)
					c.that(exp <= last, "%s: expiration %q is after the change %q: a reset would not be recognised", name, exp, last)
					c.that(e["has_password"] == true && e["has_keytab"] == true, "%s: has_password/has_keytab = %v/%v", name, e["has_password"], e["has_keytab"])
					if i == 0 {
						firstLast = last
					} else {
						c.that(last >= firstLast, "the second reset (%s) is before the first (%s)", last, firstLast)
					}
				}
				return c.err()
			},
			probes: []probe{
				set("an expiration after the change (the shape of a self-change)", "user-show-after-passwd", map[string]any{"__datetime__": "20991231235959Z"}, entryPath("krbpasswordexpiration", 0)...),
				del("no change time after a reset", "user-show-after-passwd", entryPath("krblastpwdchange")...),
				add("a change time before any password", "user-show-no-password", []any{map[string]any{"__datetime__": "20261106000000Z"}}, entryPath("krblastpwdchange")...),
				set("a policy of 30 days", "pwpolicy-show-global-at-capture", []any{"30"}, entryPath("krbmaxpwdlife")...),
				set("the second reset before the first", "user-show-after-passwd-again", []any{map[string]any{"__datetime__": "20000101000000Z"}}, entryPath("krblastpwdchange")...),
				both("the second reset before the first, both stamps", set("last", "user-show-after-passwd-again", []any{map[string]any{"__datetime__": "20000101000000Z"}}, entryPath("krblastpwdchange")...),
					set("expiration", "user-show-after-passwd-again", []any{map[string]any{"__datetime__": "20000101000000Z"}}, entryPath("krbpasswordexpiration")...)),
				del("no expiration after a reset", "user-show-after-passwd", entryPath("krbpasswordexpiration")...),
				set("a new user with a password", "user-show-no-password", true, entryPath("has_password")...),
				set("no keytab after a reset", "user-show-after-passwd", false, entryPath("has_keytab")...),
			},
		},
		{
			id: "K6 under maxlife 0 an admin reset still sets the expiration, equal to the change time",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				policy(&c, s, "pwpolicy-show-maxlife0", "krbmaxpwdlife", "0")
				e, err := s.entry("user-show-after-passwd-maxlife0")
				if !c.noError(err) {
					return c.err()
				}
				last, exp, err := resetStamps(e)
				c.noError(err)
				c.that(last != "" && exp != "" && exp <= last, "krblastpwdchange=%q krbpasswordexpiration=%q, want both set and the expiration not after the change", last, exp)
				c.that(slices.Contains(attr(e, "memberof_group"), "p24cap-pg0"), "the user is not in the group the policy belongs to: %v", attr(e, "memberof_group"))
				_, _, err = s.call(t_, "passwd-success-maxlife0", passwd("p24cap-pw0"))
				c.noError(err)
				return c.err()
			},
			probes: []probe{
				set("a policy of 90 days", "pwpolicy-show-maxlife0", []any{"90"}, entryPath("krbmaxpwdlife")...),
				del("no expiration under maxlife 0", "user-show-after-passwd-maxlife0", entryPath("krbpasswordexpiration")...),
				set("the user not in the policy's group", "user-show-after-passwd-maxlife0", []any{"ipausers"}, entryPath("memberof_group")...),
				asError("the reset refused", "passwd-success-maxlife0"),
			},
		},
		{
			id: "K6 the policy's length and character-class checks are not applied to an admin reset: a password shorter than the minimum, and one with too few classes, are accepted",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				policy(&c, s, "pwpolicy-show-global-at-capture", "krbpwdminlength", "8")
				policy(&c, s, "pwpolicy-show-classes4", "krbpwdmindiffchars", "4")
				for _, name := range []string{"passwd-short-password", "passwd-few-classes"} {
					res, _, err := s.call(t_, name, passwd("p24cap-pw"))
					if !c.noError(err) {
						continue
					}
					var r struct {
						Result bool `json:"result"`
					}
					_ = json.Unmarshal(res, &r)
					c.that(r.Result, "%s: result %v", name, r.Result)
				}
				return c.err()
			},
			probes: []probe{
				set("a global minimum of 4, which the short password would meet", "pwpolicy-show-global-at-capture", []any{"4"}, entryPath("krbpwdminlength")...),
				set("a policy that asks for no classes", "pwpolicy-show-classes4", []any{"0"}, entryPath("krbpwdmindiffchars")...),
				swap("the short password refused", "passwd-short-password", "passwd-reuse-rejected"),
				swap("the few-classes password refused", "passwd-few-classes", "passwd-reuse-rejected"),
				set("a result of false for the short password", "passwd-short-password", false, "result", "result"),
			},
		},
		{
			id: "K6 a reused password is refused when the policy keeps a history: DatabaseError 4203, an answered error that leaves the timestamps as they were",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				policy(&c, s, "pwpolicy-show-history3", "krbpwdhistorylength", "3")
				_, _, err := s.call(t_, "passwd-reuse-rejected", passwd("p24cap-pwh"))
				c.rpc("passwd with a reused password", err, "DatabaseError", 4203, "Constraint violation: Password reuse not permitted")
				d := s.errorData("passwd-reuse-rejected")
				c.that(d["desc"] == "Constraint violation" && d["info"] == "Password reuse not permitted", "error data = %v", d)
				before, errB := s.entry("user-show-before-rejected-passwd")
				after, errA := s.entry("user-show-after-rejected-passwd")
				if c.noError(errB) && c.noError(errA) {
					for _, a := range []string{"krblastpwdchange", "krbpasswordexpiration", "krbextradata"} {
						b, err := json.Marshal(before[a])
						c.noError(err)
						n, err := json.Marshal(after[a])
						c.noError(err)
						c.that(len(b) > 4 && string(b) == string(n), "%s changed across the rejected passwd: %s -> %s", a, b, n)
					}
				}
				return c.err()
			},
			probes: []probe{
				set("another error name", "passwd-reuse-rejected", "PasswordPolicyError", "error", "name"),
				set("another code", "passwd-reuse-rejected", 4204, "error", "code"),
				set("another message", "passwd-reuse-rejected", "Constraint violation: Password is too short", "error", "message"),
				set("a history of 0", "pwpolicy-show-history3", []any{"0"}, entryPath("krbpwdhistorylength")...),
				set("the change time moved by the refused call", "user-show-after-rejected-passwd", []any{map[string]any{"__datetime__": "20991231235959Z"}}, entryPath("krblastpwdchange")...),
				asSuccess("the reuse accepted", "passwd-reuse-rejected"),
				set("another info", "passwd-reuse-rejected", "x", "error", "data", "info"),
				set("another desc", "passwd-reuse-rejected", "x", "error", "data", "desc"),
			},
		},
		{
			id: "K6 passwd for a user that does not exist is EmptyResult 4031 (not NotFound); an empty password is RequirementError 3007 naming password",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, "passwd-not-found", passwd("p24cap-nobody"))
				c.rpc("passwd of a missing user", err, "EmptyResult", 4031, "no matching entry found")
				_, _, err = s.call(t_, "passwd-empty-password", passwd("p24cap-pw"))
				c.rpc("passwd with an empty password", err, "RequirementError", 3007, "'password' is required")
				c.that(s.errorData("passwd-empty-password")["name"] == "password", "the requirement names %v", s.errorData("passwd-empty-password")["name"])
				return c.err()
			},
			probes: []probe{
				set("NotFound instead of EmptyResult", "passwd-not-found", "NotFound", "error", "name"),
				set("another code for the missing user", "passwd-not-found", 4001, "error", "code"),
				set("another name for the empty password", "passwd-empty-password", "ValidationError", "error", "name"),
				set("another field named", "passwd-empty-password", "sn", "error", "data", "name"),
			},
		},
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// K7 and the recreate of K19
func factsUserDelete() []captureFact {
	del := func(uid string) Command { return Command{Method: "user_del", Args: []any{uid}} }
	deleted := func(fixture, summary string, values []string) captureFact {
		return captureFact{
			id: "K7 user_del " + fixture + ": the result says what it removed and that nothing failed",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				res, _, err := s.call(t_, fixture, del("x"))
				if !c.noError(err) {
					return c.err()
				}
				var r struct {
					Result  struct{ Failed []any } `json:"result"`
					Value   []string               `json:"value"`
					Summary string                 `json:"summary"`
				}
				_ = json.Unmarshal(res, &r)
				c.that(r.Summary == summary, "summary = %q, want %q", r.Summary, summary)
				c.that(slices.Equal(r.Value, values), "value = %v, want %v", r.Value, values)
				c.that(r.Result.Failed != nil && len(r.Result.Failed) == 0, "result.failed = %v, want an empty list", r.Result.Failed)
				return c.err()
			},
			probes: []probe{
				set("another summary", fixture, "Deleted something", "result", "summary"),
				set("another value", fixture, []any{"p24cap-other"}, "result", "value"),
				set("something failed", fixture, []any{"p24cap-x"}, "result", "result", "failed"),
				asError("an error instead", fixture),
			},
		}
	}
	notFound := func(fixture, message string) captureFact {
		return captureFact{
			id: "K7 " + fixture + " is NotFound 4001, which the writer reads as already gone (noop)",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, fixture, del("x"))
				c.rpc(fixture, err, "NotFound", 4001, message)
				return c.err()
			},
			probes: []probe{
				set("another name", fixture, "EmptyResult", "error", "name"),
				set("another code", fixture, 4031, "error", "code"),
				asSuccess("a success instead", fixture),
			},
		}
	}
	return []captureFact{
		deleted("user-del", `Deleted user "p24cap-ux"`, []string{"p24cap-ux"}),
		notFound("user-del-not-found", "p24cap-ux: user not found"),
		deleted("user-del-preserved", `Deleted user "p24cap-up"`, []string{"p24cap-up"}),
		{
			id: "K7 deleting a user takes it out of its groups and removes its private group",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				before, errB := s.entry("group-show-before-user-del")
				after, errA := s.entry("group-show-after-user-del")
				if c.noError(errB) && c.noError(errA) {
					c.that(slices.Contains(attr(before, "member_user"), "p24cap-ux"), "the user was not a member before: %v", attr(before, "member_user"))
					c.that(!slices.Contains(attr(after, "member_user"), "p24cap-ux"), "the deleted user is still a member: %v", attr(after, "member_user"))
				}
				_, err := s.entry("group-show-private-group-before-user-del")
				c.noError(err)
				re, err := s.errorOf("group-show-private-group-after-user-del")
				if c.noError(err) {
					c.that(re.Name == "NotFound" && re.Code == 4001, "private group after the delete: %s (%d)", re.Name, re.Code)
				}
				return c.err()
			},
			probes: []probe{
				set("the deleted user still a member", "group-show-after-user-del", []any{"p24cap-ud", "p24cap-ux"}, entryPath("member_user")...),
				set("the user not a member before", "group-show-before-user-del", []any{"p24cap-ud"}, entryPath("member_user")...),
				asSuccess("the private group still there", "group-show-private-group-after-user-del"),
				asError("no private group before", "group-show-private-group-before-user-del"),
				set("another name for the missing private group", "group-show-private-group-after-user-del", "EmptyResult", "error", "name"),
			},
		},
		{
			id: "K7/K19 user_del with preserve keeps the account as a preserved user: found by user_show with preserved=true, disabled, out of its groups, its name taken, and a plain user_del removes it for good",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				res, _, err := s.call(t_, "user-del-preserve", Command{Method: "user_del", Args: []any{"p24cap-up"}, Options: map[string]any{"preserve": true}})
				if c.noError(err) {
					var r struct {
						Summary string   `json:"summary"`
						Value   []string `json:"value"`
					}
					_ = json.Unmarshal(res, &r)
					c.that(r.Summary == `Preserved user "p24cap-up"` && slices.Equal(r.Value, []string{"p24cap-up"}), "answer = %q %v", r.Summary, r.Value)
				}
				e, err := s.entry("user-show-preserved")
				if c.noError(err) {
					c.that(e["preserved"] == true, "preserved = %v", e["preserved"])
					c.that(e["nsaccountlock"] == true, "a preserved user is not locked: %v", e["nsaccountlock"])
					c.that(strings.Contains(fmt.Sprint(e["dn"]), "cn=deleted users,"), "dn = %v", e["dn"])
					_, has := e["memberof_group"]
					c.that(!has, "a preserved user still has memberof_group %v", e["memberof_group"])
					c.that(slices.Equal(attr(e, "uid"), []string{"p24cap-up"}) && len(attr(e, "ipauniqueid")) == 1, "uid/ipauniqueid = %v/%v", attr(e, "uid"), attr(e, "ipauniqueid"))
				}
				before, errB := s.entry("group-show-after-user-del")
				after, errA := s.entry("group-show-after-preserve")
				if c.noError(errB) && c.noError(errA) {
					c.that(slices.Contains(attr(before, "member_user"), "p24cap-up") && !slices.Contains(attr(after, "member_user"), "p24cap-up"),
						"member_user %v -> %v: the preserved user should leave the group", attr(before, "member_user"), attr(after, "member_user"))
				}
				_, _, err = s.call(t_, "user-add-duplicate-preserved", Command{Method: "user_add", Args: []any{"p24cap-up"}})
				c.rpc("user_add of a preserved user's name", err, "DuplicateEntry", 4002, `user with name "p24cap-up" already exists`)
				nf, err := s.errorOf("user-show-after-permanent-delete")
				if c.noError(err) {
					c.that(nf.Name == "NotFound", "after the permanent delete: %s", nf.Name)
				}
				return c.err()
			},
			probes: []probe{
				set("not preserved", "user-show-preserved", false, entryPath("preserved")...),
				set("not locked", "user-show-preserved", false, entryPath("nsaccountlock")...),
				set("a live dn", "user-show-preserved", "uid=p24cap-up,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal", entryPath("dn")...),
				add("still in a group", "user-show-preserved", []any{"p24cap-gu"}, entryPath("memberof_group")...),
				set("still a member of the group", "group-show-after-preserve", []any{"p24cap-ud", "p24cap-up"}, entryPath("member_user")...),
				set("the name free", "user-add-duplicate-preserved", "NotFound", "error", "name"),
				asSuccess("the preserved user still there after the delete", "user-show-after-permanent-delete"),
				asError("the preserve refused", "user-del-preserve"),
				set("another summary for the preserve", "user-del-preserve", `Deleted user "p24cap-up"`, "result", "summary"),
				set("another account preserved", "user-del-preserve", []any{"p24cap-other"}, "result", "value"),
				set("another uid on the preserved user", "user-show-preserved", []any{"x"}, entryPath("uid")...),
				set("another name after the permanent delete", "user-show-after-permanent-delete", "EmptyResult", "error", "name"),
			},
		},
		{
			id: "K19 a user deleted and added again under the same name is another account: ipauniqueid, uidnumber and gidnumber all differ; the same for a group",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				for _, pair := range [][2]string{{"user-show-before-recreate", "user-show-after-recreate"}, {"group-show-before-recreate", "group-show-after-recreate"}} {
					a, errA := s.entry(pair[0])
					b, errB := s.entry(pair[1])
					if !c.noError(errA) || !c.noError(errB) {
						continue
					}
					attrs := []string{"ipauniqueid", "gidnumber"}
					if strings.HasPrefix(pair[0], "user") {
						attrs = append(attrs, "uidnumber")
					}
					for _, k := range attrs {
						x, y := attr(a, k), attr(b, k)
						c.that(len(x) == 1 && len(y) == 1 && x[0] != y[0], "%s: %s %v -> %v, want a different value", pair[0], k, x, y)
					}
					c.that(len(attr(a, "ipauniqueid")) == 1 && uuidRe.MatchString(attr(a, "ipauniqueid")[0]), "ipauniqueid = %v", attr(a, "ipauniqueid"))
				}
				return c.err()
			},
			probes: []probe{
				copyValue("the same ipauniqueid after a recreate", "user-show-before-recreate", "user-show-after-recreate", entryPath("ipauniqueid")...),
				copyValue("the same uidnumber after a recreate", "user-show-before-recreate", "user-show-after-recreate", entryPath("uidnumber")...),
				copyValue("the same gidnumber for the group", "group-show-before-recreate", "group-show-after-recreate", entryPath("gidnumber")...),
				copyValue("the same ipauniqueid for the group", "group-show-before-recreate", "group-show-after-recreate", entryPath("ipauniqueid")...),
				set("a malformed ipauniqueid", "user-show-before-recreate", []any{"not-a-uuid"}, entryPath("ipauniqueid")...),
			},
		},
	}
}

// K8, K9, K11
func factsGroupWrites() []captureFact {
	groupDel := func(name string) Command { return Command{Method: "group_del", Args: []any{name}} }
	groupMod := func(name string) Command {
		return Command{Method: "group_mod", Args: []any{name}, Options: map[string]any{"description": "x"}}
	}
	return []captureFact{
		{
			id: "K8 group_del succeeds with the group name, nothing failed; NotFound 4001 when it is gone (noop)",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				res, _, err := s.call(t_, "group-del", groupDel("p24cap-gd"))
				if c.noError(err) {
					var r struct {
						Result  struct{ Failed []any } `json:"result"`
						Value   []string               `json:"value"`
						Summary string                 `json:"summary"`
					}
					_ = json.Unmarshal(res, &r)
					c.that(r.Summary == `Deleted group "p24cap-gd"` && slices.Equal(r.Value, []string{"p24cap-gd"}) && r.Result.Failed != nil && len(r.Result.Failed) == 0, "answer = %+v", r)
				}
				_, _, err = s.call(t_, "group-del-not-found", groupDel("p24cap-gd"))
				c.rpc("group_del of a deleted group", err, "NotFound", 4001, "p24cap-gd: group not found")
				return c.err()
			},
			probes: []probe{
				set("another summary", "group-del", "Deleted something", "result", "summary"),
				set("a failure listed", "group-del", []any{"p24cap-gd"}, "result", "result", "failed"),
				set("another name for the missing group", "group-del-not-found", "EmptyResult", "error", "name"),
				asSuccess("the missing group deleted", "group-del-not-found"),
			},
		},
		{
			id: "K8 deleting a group that has members and is a member removes it from its parents' and members' lists",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, "group-del-with-members", groupDel("p24cap-mdel"))
				c.noError(err)
				gb, errB := s.entry("group-show-before-member-group-del")
				ga, errA := s.entry("group-show-after-member-group-del")
				if c.noError(errB) && c.noError(errA) {
					c.that(slices.Equal(attr(gb, "member_group"), []string{"p24cap-mdel"}), "parent before: member_group %v", attr(gb, "member_group"))
					_, has := ga["member_group"]
					c.that(!has, "parent after: member_group %v", ga["member_group"])
					_, has = ga["memberindirect_user"]
					c.that(!has, "parent after: memberindirect_user %v", ga["memberindirect_user"])
				}
				ub, errB := s.entry("user-show-before-member-group-del")
				ua, errA := s.entry("user-show-after-member-group-del")
				if c.noError(errB) && c.noError(errA) {
					c.that(slices.Contains(attr(ub, "memberof_group"), "p24cap-mdel"), "member before: memberof_group %v", attr(ub, "memberof_group"))
					c.that(!slices.Contains(attr(ua, "memberof_group"), "p24cap-mdel"), "member after: memberof_group %v", attr(ua, "memberof_group"))
				}
				return c.err()
			},
			probes: []probe{
				add("the deleted group still a member", "group-show-after-member-group-del", []any{"p24cap-mdel"}, entryPath("member_group")...),
				add("its user still an indirect member", "group-show-after-member-group-del", []any{"p24cap-m1"}, entryPath("memberindirect_user")...),
				set("the group not a member before", "group-show-before-member-group-del", []any{"p24cap-other"}, entryPath("member_group")...),
				set("the user still in the deleted group", "user-show-after-member-group-del", []any{"ipausers", "p24cap-mdel"}, entryPath("memberof_group")...),
				set("the user not in the group before", "user-show-before-member-group-del", []any{"ipausers"}, entryPath("memberof_group")...),
				asError("the delete refused", "group-del-with-members"),
			},
		},
		{
			id: "K9 group_mod succeeds with the group name as a string; the same description is EmptyModlist 4202 (noop); a missing group is NotFound 4001",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				res, _, err := s.call(t_, "group-mod-description", groupMod("p24cap-g1"))
				if c.noError(err) {
					var r struct {
						Result struct {
							Description []string `json:"description"`
						} `json:"result"`
						Value   string `json:"value"`
						Summary string `json:"summary"`
					}
					_ = json.Unmarshal(res, &r)
					c.that(r.Value == "p24cap-g1" && r.Summary == `Modified group "p24cap-g1"` && slices.Equal(r.Result.Description, []string{"P24 group one, changed"}), "answer = %+v", r)
				}
				_, _, err = s.call(t_, "group-mod-no-change", groupMod("p24cap-g1"))
				c.rpc("group_mod with the same description", err, "EmptyModlist", 4202, "no modifications to be performed")
				_, _, err = s.call(t_, "group-mod-not-found", groupMod("p24cap-gx"))
				c.rpc("group_mod of a missing group", err, "NotFound", 4001, "p24cap-gx: group not found")
				return c.err()
			},
			probes: []probe{
				set("another description in the answer", "group-mod-description", []any{"other"}, entryPath("description")...),
				set("a list for the value", "group-mod-description", []any{"p24cap-g1"}, "result", "value"),
				set("another code for no change", "group-mod-no-change", 4001, "error", "code"),
				set("another name for no change", "group-mod-no-change", "NotFound", "error", "name"),
				set("another name for the missing group", "group-mod-not-found", "EmptyModlist", "error", "name"),
			},
		},
		{
			id: "K11 group_add of a name that is taken is DuplicateEntry 4002 (conflict), whichever case it is spelled in and whether the name is a group or a user's private group",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				for fixture, name := range map[string]string{
					"group-add-duplicate":               "p24cap-g1",
					"group-add-duplicate-case":          "p24cap-g1",
					"group-add-duplicate-private-group": "p24cap-gdup",
				} {
					_, _, err := s.call(t_, fixture, Command{Method: "group_add", Args: []any{name}, Options: map[string]any{"description": "x"}})
					c.rpc(fixture, err, "DuplicateEntry", 4002, fmt.Sprintf("group with name %q already exists", name))
				}
				return c.err()
			},
			probes: []probe{
				set("another name", "group-add-duplicate", "ValidationError", "error", "name"),
				set("the case-variant message naming the request", "group-add-duplicate-case", `group with name "P24CAP-G1" already exists`, "error", "message"),
				set("another code for the private group", "group-add-duplicate-private-group", 4001, "error", "code"),
				asSuccess("the duplicate accepted", "group-add-duplicate"),
			},
		},
	}
}

// markerOfCapture is HistoryMarkerName of the roster group the harness used.
var markerOfCapture = markerOf("p24cap-gmk")

// K10
func factsMarker() []captureFact {
	wantClasses := []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"}
	desc := "pilot.group-history/v1 name=p24cap-gmk"
	markerEntry := func(c *factCheck, what string, e map[string]any) {
		c.that(slices.Equal(attr(e, "cn"), []string{markerOfCapture}), "%s: cn = %v, want the marker name of the roster group", what, attr(e, "cn"))
		c.that(sameSet(attr(e, "objectclass"), wantClasses), "%s: objectclass = %v, want %v", what, attr(e, "objectclass"), wantClasses)
		_, has := e["gidnumber"]
		c.that(!has, "%s: a non-posix marker has a gidnumber %v", what, e["gidnumber"])
	}
	return []captureFact{
		{
			id: "K10 a non-posix group_add with a description is the marker: no gidnumber, no posixgroup, the description as given",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				cmd := Command{Method: "group_add", Args: []any{markerOfCapture}, Options: map[string]any{"nonposix": true, "description": desc}}
				_, _, err := s.call(t_, "group-add-marker", cmd)
				c.noError(err)
				e, err := s.entry("group-add-marker")
				if c.noError(err) {
					markerEntry(&c, "group_add", e)
					c.that(slices.Equal(attr(e, "description"), []string{desc}), "group_add: description = %v", attr(e, "description"))
				}
				return c.err()
			},
			probes: []probe{
				set("another description", "group-add-marker", []any{"pilot.group-history/v1 name=other"}, entryPath("description")...),
				add("a gidnumber", "group-add-marker", []any{"1000"}, entryPath("gidnumber")...),
				set("a posix object class", "group-add-marker", []any{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject", "posixgroup"}, entryPath("objectclass")...),
				set("another group name", "group-add-marker", []any{"pilot-internal-history-g-0000"}, entryPath("cn")...),
			},
		},
		{
			id: "K10 group_show and group_find read the marker back with the same name, object classes and description; one group matched, nothing truncated",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				e, err := s.entry("group-show-marker")
				if c.noError(err) {
					markerEntry(&c, "group_show", e)
					c.that(slices.Equal(attr(e, "description"), []string{desc}), "group_show: description = %v", attr(e, "description"))
				}
				found, err := s.find(t_, "group-find-marker", "group_find", map[string]any{"all": true})
				if c.noError(err) {
					c.that(len(found) == 1, "group_find returned %d groups", len(found))
					if len(found) == 1 {
						markerEntry(&c, "group_find", found[0])
						c.that(slices.Equal(attr(found[0], "description"), []string{desc}), "group_find: description = %v", attr(found[0], "description"))
						if e != nil {
							c.that(slices.Equal(attr(found[0], "ipauniqueid"), attr(e, "ipauniqueid")), "group_find and group_show disagree on ipauniqueid")
						}
					}
				}
				return c.err()
			},
			probes: []probe{
				set("another description in group_show", "group-show-marker", []any{"x"}, entryPath("description")...),
				set("a posix group in group_find", "group-find-marker", []any{"top", "groupofnames", "posixgroup"}, "result", "result", 0, "objectclass"),
				set("two groups matched", "group-find-marker", 2, "result", "count"),
				set("a truncated find", "group-find-marker", true, "result", "truncated"),
				set("another ipauniqueid in group_find", "group-find-marker", []any{"00000000-0000-0000-0000-000000000000"}, "result", "result", 0, "ipauniqueid"),
				set("another description in group_find", "group-find-marker", []any{"x"}, "result", "result", 0, "description"),
				{"two groups returned", func(s *captureSet) {
					s.edit("group-find-marker", []any{"result", "count"}, func(parent, key any) { parent.(map[string]any)["count"] = 2 })
					s.edit("group-find-marker", []any{"result", "result"}, func(parent, key any) {
						m := parent.(map[string]any)
						m["result"] = append(m["result"].([]any), m["result"].([]any)[0])
					})
				}},
			},
		},
		{
			id: "K10 a second marker add is DuplicateEntry 4002; a marker whose description was changed reads back with that description and the same group identity",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, "group-add-marker-duplicate", Command{Method: "group_add", Args: []any{markerOfCapture}, Options: map[string]any{"nonposix": true}})
				c.rpc("second marker add", err, "DuplicateEntry", 4002, fmt.Sprintf("group with name %q already exists", markerOfCapture))
				orig, errO := s.entry("group-show-marker")
				changed, errC := s.entry("group-show-marker-changed")
				if c.noError(errO) && c.noError(errC) {
					c.that(!slices.Equal(attr(changed, "description"), []string{desc}), "the changed marker still has the expected description")
					c.that(slices.Equal(attr(changed, "ipauniqueid"), attr(orig, "ipauniqueid")), "the changed marker is another group")
					markerEntry(&c, "changed marker", changed)
				}
				return c.err()
			},
			probes: []probe{
				set("another error name", "group-add-marker-duplicate", "EmptyModlist", "error", "name"),
				set("the description unchanged", "group-show-marker-changed", []any{desc}, entryPath("description")...),
				set("another group", "group-show-marker-changed", []any{"00000000-0000-0000-0000-000000000000"}, entryPath("ipauniqueid")...),
			},
		},
	}
}

// memberRow is one membership capture.
type memberRow struct {
	fixture   string
	cmd       Command
	requested int
	completed int
	failed    []MemberFailure
}

func memberCommand(method, group, kind string, names ...string) Command {
	list := make([]any, len(names))
	for i, n := range names {
		list[i] = n
	}
	return Command{Method: method, Args: []any{group}, Options: map[string]any{kind: list}}
}

// K12, K13
func factsMembers() []captureFact {
	rows := []memberRow{
		{"group-add-member-group", memberCommand("group_add_member", "p24cap-mg1", "group", "p24cap-mg2"), 1, 1, nil},
		{"group-add-member-group-already", memberCommand("group_add_member", "p24cap-mg1", "group", "p24cap-mg2"), 1, 0, []MemberFailure{{"group", "p24cap-mg2", "This entry is already a member"}}},
		{"group-add-member-group-missing", memberCommand("group_add_member", "p24cap-mg1", "group", "p24cap-nogroup"), 1, 0, []MemberFailure{{"group", "p24cap-nogroup", "no such entry"}}},
		{"group-add-member-group-itself", memberCommand("group_add_member", "p24cap-mg1", "group", "p24cap-mg1"), 1, 0, []MemberFailure{{"group", "p24cap-mg1", "A group may not be added as a member of itself"}}},
		{"group-add-member-groups-two", memberCommand("group_add_member", "p24cap-mg1", "group", "p24cap-mg3"), 1, 1, nil},
		{"group-remove-member-users", memberCommand("group_remove_member", "p24cap-mg1", "user", "p24cap-m1", "p24cap-m2"), 2, 2, nil},
		{"group-remove-member-group", memberCommand("group_remove_member", "p24cap-mg1", "group", "p24cap-mg2"), 1, 1, nil},
		{"group-remove-member-group-mixed", memberCommand("group_remove_member", "p24cap-mg1", "group", "p24cap-mg3", "p24cap-mg2"), 2, 1, []MemberFailure{{"group", "p24cap-mg2", "This entry is not a member"}}},
		{"group-remove-member-no-such-entry", memberCommand("group_remove_member", "p24cap-mg1", "user", "p24cap-nobody"), 1, 0, []MemberFailure{{"user", "p24cap-nobody", "This entry is not a member"}}},
		{"group-remove-member-group-no-such-entry", memberCommand("group_remove_member", "p24cap-mg1", "group", "p24cap-nogroup"), 1, 0, []MemberFailure{{"group", "p24cap-nogroup", "This entry is not a member"}}},
		{"group-add-member-group-cycle", memberCommand("group_add_member", "p24cap-cg2", "group", "p24cap-cg1"), 1, 1, nil},
	}
	var facts []captureFact
	for _, row := range rows {
		probes := []probe{
			set("one more member completed than asked", row.fixture, row.completed+row.requested, "result", "completed"),
			del("no failed.member", row.fixture, "result", "failed", "member"),
		}
		for _, f := range row.failed {
			probes = append(probes, set("another reason", row.fixture, "something else", "result", "failed", "member", f.Type, 0, 1))
			probes = append(probes, set("another member named", row.fixture, "p24cap-other", "result", "failed", "member", f.Type, 0, 0))
			// the accounting still adds up, with the split changed
			probes = append(probes, both("a failure counted as completed",
				set("completed", row.fixture, row.completed+len(row.failed), "result", "completed"),
				set("failed", row.fixture, []any{}, "result", "failed", "member", f.Type)))
		}
		if len(row.failed) == 0 {
			kind := "group"
			for k := range row.cmd.Options {
				kind = k
			}
			probes = append(probes, both("a completed member counted as failed",
				set("completed", row.fixture, row.completed-1, "result", "completed"),
				set("failed", row.fixture, []any{[]any{"p24cap-x", "no such entry"}}, "result", "failed", "member", kind)))
		}
		facts = append(facts, captureFact{
			id: "K12/K13 " + row.fixture + ": every requested member is accounted for, as completed or as failed with FreeIPA's reason, in an answer that is a success either way",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				res, _, err := s.call(t_, row.fixture, row.cmd)
				if !c.noError(err) {
					return c.err()
				}
				got, err := DecodeMemberResult(res, row.requested)
				if !c.noError(err) {
					return c.err()
				}
				c.that(got.Completed == row.completed && slices.Equal(got.Failed, row.failed), "completed %d and failed %v, want %d and %v", got.Completed, got.Failed, row.completed, row.failed)
				return c.err()
			},
			probes: probes,
		})
	}
	facts = append(facts,
		captureFact{
			id: "K12/K13 a member command on a group that does not exist is NotFound 4001 (a conflict for an addition), whichever of the two commands it is",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, "group-add-member-to-missing-group", memberCommand("group_add_member", "p24cap-nogroup", "group", "p24cap-mg2"))
				c.rpc("group_add_member to a missing group", err, "NotFound", 4001, "p24cap-nogroup: group not found")
				_, _, err = s.call(t_, "group-remove-member-from-missing-group", memberCommand("group_remove_member", "p24cap-nogroup", "user", "p24cap-m1"))
				c.rpc("group_remove_member from a missing group", err, "NotFound", 4001, "p24cap-nogroup: group not found")
				return c.err()
			},
			probes: []probe{
				set("another name for the addition", "group-add-member-to-missing-group", "EmptyResult", "error", "name"),
				set("another code for the removal", "group-remove-member-from-missing-group", 4031, "error", "code"),
				asSuccess("the removal accepted", "group-remove-member-from-missing-group"),
			},
		},
		captureFact{
			id: "K13 FreeIPA accepts a loop of groups (A in B, B in A) as it accepts any other addition: the answer is a success and each group lists the other, and itself as an indirect member",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				e, err := s.entry("group-show-cycle")
				if c.noError(err) {
					c.that(slices.Equal(attr(e, "member_group"), []string{"p24cap-cg2"}), "member_group = %v", attr(e, "member_group"))
					c.that(slices.Equal(attr(e, "memberof_group"), []string{"p24cap-cg2"}), "memberof_group = %v", attr(e, "memberof_group"))
					c.that(slices.Contains(attr(e, "memberindirect_group"), "p24cap-cg1"), "memberindirect_group = %v does not list the group itself", attr(e, "memberindirect_group"))
				}
				return c.err()
			},
			probes: []probe{
				set("no loop: the group is not a member of the other", "group-show-cycle", []any{"p24cap-other"}, entryPath("memberof_group")...),
				del("no indirect member: the loop is not visible", "group-show-cycle", entryPath("memberindirect_group")...),
				set("another direct member", "group-show-cycle", []any{"p24cap-other"}, entryPath("member_group")...),
			},
		},
	)
	return facts
}

// K14
func factsUserFields() []captureFact {
	userAdd := func() Command { return Command{Method: "user_add", Args: []any{"x"}} }
	userMod := func() Command { return Command{Method: "user_mod", Args: []any{"x"}} }
	values := func(c *factCheck, what string, e map[string]any, want map[string][]string) {
		for k, v := range want {
			c.that(slices.Equal(attr(e, k), v), "%s: %s = %v, want %v", what, k, attr(e, k), v)
		}
	}
	return []captureFact{
		{
			id: "K14 user_add takes givenname, sn, displayname, mail, loginshell and homedirectory, and keeps them as given; mail is exactly the one given (no default address beside it)",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				want := map[string][]string{
					"givenname": {"P24"}, "sn": {"One"}, "displayname": {"P24 One Display"}, "mail": {"p24cap-u1@example.test"},
					"loginshell": {"/bin/bash"}, "homedirectory": {"/srv/home/p24cap-u1"},
				}
				_, _, err := s.call(t_, "user-add-all-options", userAdd())
				c.noError(err)
				for _, name := range []string{"user-add-all-options", "user-show-all-options"} {
					e, err := s.entry(name)
					if c.noError(err) {
						values(&c, name, e, want)
					}
				}
				return c.err()
			},
			probes: []probe{
				set("another display name", "user-add-all-options", []any{"x"}, entryPath("displayname")...),
				set("a default address beside the given one", "user-add-all-options", []any{"p24cap-u1@example.test", "p24cap-u1@ipa.pilot.internal"}, entryPath("mail")...),
				set("another shell read back", "user-show-all-options", []any{"/bin/sh"}, entryPath("loginshell")...),
				set("another home read back", "user-show-all-options", []any{"/home/p24cap-u1"}, entryPath("homedirectory")...),
			},
		},
		{
			id: "K14 what FreeIPA fills in when the options are left out: mail uid@domain, shell /bin/sh, home /home/uid, displayname and cn from the names",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				e, err := s.entry("user-add-default-mail")
				if c.noError(err) {
					values(&c, "user_add with names only", e, map[string][]string{
						"mail": {"p24cap-u2@ipa.pilot.internal"}, "loginshell": {"/bin/sh"}, "homedirectory": {"/home/p24cap-u2"},
						"displayname": {"P24 Two"}, "cn": {"P24 Two"},
					})
				}
				return c.err()
			},
			probes: []probe{
				set("no default address", "user-add-default-mail", []any{"x@example.test"}, entryPath("mail")...),
				del("no default shell", "user-add-default-mail", entryPath("loginshell")...),
				set("another default home", "user-add-default-mail", []any{"/srv/p24cap-u2"}, entryPath("homedirectory")...),
			},
		},
		{
			id: "K14 mail is a set that one user_mod replaces whole: a list or a string of the same addresses is EmptyModlist, in any order; a different case is a change",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				a, errA := s.entry("user-add-mail-two")
				r, errR := s.entry("user-mod-mail-replace")
				shown, errS := s.entry("user-show-after-mail-replace")
				if c.noError(errA) && c.noError(errR) && c.noError(errS) {
					c.that(sameSet(attr(a, "mail"), []string{"p24cap-u3-a@example.test", "p24cap-u3-b@example.test"}), "two addresses at the add: %v", attr(a, "mail"))
					c.that(slices.Equal(attr(r, "mail"), []string{"p24cap-u3-c@example.test"}), "after the replace (answer): %v", attr(r, "mail"))
					c.that(slices.Equal(attr(shown, "mail"), []string{"p24cap-u3-c@example.test"}), "after the replace (read back): %v: the earlier two must be gone", attr(shown, "mail"))
				}
				for _, name := range []string{"user-mod-mail-same", "user-mod-mail-same-string", "user-mod-mail-two-reordered"} {
					_, _, err := s.call(t_, name, userMod())
					c.rpc(name, err, "EmptyModlist", 4202, "no modifications to be performed")
				}
				cs, errC := s.entry("user-mod-mail-case")
				if c.noError(errC) {
					c.that(slices.Equal(attr(cs, "mail"), []string{"P24CAP-U3-C@EXAMPLE.TEST"}), "a change of case: %v", attr(cs, "mail"))
				}
				two, errT := s.entry("user-mod-mail-two")
				if c.noError(errT) {
					c.that(sameSet(attr(two, "mail"), []string{"p24cap-u3-a@example.test", "p24cap-u3-b@example.test"}), "two addresses again: %v", attr(two, "mail"))
				}
				return c.err()
			},
			probes: []probe{
				set("the two old addresses kept beside the new one", "user-show-after-mail-replace", []any{"p24cap-u3-c@example.test", "p24cap-u3-a@example.test"}, entryPath("mail")...),
				set("another address in the replace answer", "user-mod-mail-replace", []any{"x@example.test"}, entryPath("mail")...),
				set("one address only at the add", "user-add-mail-two", []any{"p24cap-u3-a@example.test"}, entryPath("mail")...),
				set("one address only when set to two again", "user-mod-mail-two", []any{"p24cap-u3-a@example.test"}, entryPath("mail")...),
				asSuccess("the same set accepted as a change", "user-mod-mail-same"),
				asSuccess("the string form accepted as a change", "user-mod-mail-same-string"),
				asSuccess("a reorder accepted as a change", "user-mod-mail-two-reordered"),
				set("the case change stored in lower case", "user-mod-mail-case", []any{"p24cap-u3-c@example.test"}, entryPath("mail")...),
				asError("the case change refused", "user-mod-mail-case"),
			},
		},
		{
			id: "K14 a user_mod changes only the options it carries: a shell alone leaves the names and home as they were, and the derived cn, gecos and initials are not recomputed",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				m, err := s.entry("user-mod-fields")
				if c.noError(err) {
					values(&c, "user-mod-fields", m, map[string][]string{
						"givenname": {"P24x"}, "sn": {"Onex"}, "displayname": {"P24 One Display 2"},
						"loginshell": {"/bin/zsh"}, "homedirectory": {"/srv/home/p24cap-u1-2"},
					})
				}
				one, err := s.entry("user-mod-loginshell-only")
				if c.noError(err) {
					values(&c, "user-mod-loginshell-only", one, map[string][]string{
						"loginshell": {"/bin/sh"}, "givenname": {"P24x"}, "sn": {"Onex"}, "homedirectory": {"/srv/home/p24cap-u1-2"},
					})
				}
				shown, err := s.entry("user-show-after-loginshell-only")
				if c.noError(err) {
					values(&c, "after the changes", shown, map[string][]string{
						"cn": {"P24 One"}, "gecos": {"P24 One"}, "initials": {"PO"}, "givenname": {"P24x"}, "displayname": {"P24 One Display 2"},
						"loginshell": {"/bin/sh"}, "homedirectory": {"/srv/home/p24cap-u1-2"},
					})
				}
				_, _, err = s.call(t_, "user-mod-loginshell-no-change", userMod())
				c.rpc("user_mod with the shell it has", err, "EmptyModlist", 4202, "no modifications to be performed")
				return c.err()
			},
			probes: []probe{
				set("another surname in the multi-option answer", "user-mod-fields", []any{"x"}, entryPath("sn")...),
				set("the shell-only answer changing the home", "user-mod-loginshell-only", []any{"/home/x"}, entryPath("homedirectory")...),
				set("cn recomputed from the new names", "user-show-after-loginshell-only", []any{"P24x Onex"}, entryPath("cn")...),
				set("another shell read back", "user-show-after-loginshell-only", []any{"/bin/zsh"}, entryPath("loginshell")...),
				asSuccess("no change accepted as a change", "user-mod-loginshell-no-change"),
			},
		},
		{
			id: "K14 user_mod, user_enable and user_disable of a missing user are NotFound 4001 (a conflict, not a noop); the messages differ",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				_, _, err := s.call(t_, "user-mod-not-found", userMod())
				c.rpc("user_mod", err, "NotFound", 4001, "p24cap-nobody: user not found")
				_, _, err = s.call(t_, "user-enable-not-found", Command{Method: "user_enable", Args: []any{"x"}})
				c.rpc("user_enable", err, "NotFound", 4001, "no such entry")
				_, _, err = s.call(t_, "user-disable-not-found", Command{Method: "user_disable", Args: []any{"x"}})
				c.rpc("user_disable", err, "NotFound", 4001, "no such entry")
				return c.err()
			},
			probes: []probe{
				set("another name for the mod", "user-mod-not-found", "EmptyResult", "error", "name"),
				set("another code for the enable", "user-enable-not-found", 4031, "error", "code"),
				set("another message for the disable", "user-disable-not-found", "user not found", "error", "message"),
			},
		},
		{
			id: "K14 an option name that is not the API's (the CLI's first, the roster's display_name) is refused with OptionError 3005 naming it, not ignored",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				for fixture, option := range map[string]string{"user-add-unknown-option-first": "first", "user-add-unknown-option-display-name": "display_name"} {
					_, _, err := s.call(t_, fixture, userAdd())
					c.rpc(fixture, err, "OptionError", 3005, "Unknown option: "+option)
					c.that(s.errorData(fixture)["option"] == option, "%s: the error names %v", fixture, s.errorData(fixture)["option"])
				}
				return c.err()
			},
			probes: []probe{
				set("another error name", "user-add-unknown-option-first", "ValidationError", "error", "name"),
				set("another option named", "user-add-unknown-option-display-name", "email", "error", "data", "option"),
				asSuccess("the option accepted", "user-add-unknown-option-first"),
			},
		},
	}
}

// K15, K19
func factsBatches() []captureFact {
	type item struct {
		method string
		err    string // the error name, "" for a success
		code   int
	}
	cmds := func(items []item) []Command {
		out := make([]Command, len(items))
		for i, it := range items {
			out[i] = Command{Method: it.method, Args: []any{"x"}}
		}
		return out
	}
	batchFact := func(id, fixture string, items []item, extra func(c *factCheck, s *captureSet, got []BatchItem), probes ...probe) captureFact {
		return captureFact{
			id: id,
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				got, _, err := s.batch(t_, fixture, cmds(items)...)
				if !c.noError(err) {
					return c.err()
				}
				for i, it := range items {
					if it.err == "" {
						c.that(got[i].Err == nil && got[i].Result != nil, "item %d (%s): %+v, want a success", i, it.method, got[i].Err)
					} else {
						c.that(got[i].Err != nil && got[i].Err.Name == it.err && got[i].Err.Code == it.code, "item %d (%s): %+v, want %s (%d)", i, it.method, got[i].Err, it.err, it.code)
					}
				}
				if extra != nil && len(c.problems) == 0 {
					extra(&c, s, got)
				}
				return c.err()
			},
			probes: probes,
		}
	}
	itemValue := func(c *factCheck, raw json.RawMessage, what string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("%s: %v", what, err)) // decodeBatch has already read it as an object
		}
		return m
	}
	return []captureFact{
		batchFact("K15 a write batch with a DuplicateEntry item in the middle answers every item, and the item after the failure was applied (a batch is not a transaction)",
			"batch-group-add-duplicate",
			[]item{{"group_add", "", 0}, {"group_add", "DuplicateEntry", 4002}, {"group_add", "", 0}},
			func(c *factCheck, s *captureSet, got []BatchItem) {
				names := map[string]bool{}
				e := s.doc("group-find-after-batch")
				res, _ := e["result"].(map[string]any)
				list, _ := res["result"].([]any)
				for _, g := range list {
					names[strings.Join(attr(g.(map[string]any), "cn"), ",")] = true
				}
				c.that(names["p24cap-b1"] && names["p24cap-b2"], "the groups found after the batch are %v: the item after the failure was not applied", names)
				v := itemValue(c, got[2].Result, "item 2")
				c.that(v["value"] == "p24cap-b2", "item 2 value = %v", v["value"])
			},
			set("the duplicate item succeeding", "batch-group-add-duplicate", nil, "result", "results", 1, "error"),
			set("another error name", "batch-group-add-duplicate", "NotFound", "result", "results", 1, "error_name"),
			set("another code", "batch-group-add-duplicate", 4001, "result", "results", 1, "error_code"),
			set("the later group missing after the batch", "group-find-after-batch", []any{}, "result", "result"),
			del("a result missing", "batch-group-add-duplicate", "result", "results", 0, "result"),
			both("a success item turned into an error item",
				set("error", "batch-group-add-duplicate", "boom", "result", "results", 0, "error"),
				add("name", "batch-group-add-duplicate", "NotFound", "result", "results", 0, "error_name"),
				add("code", "batch-group-add-duplicate", 4001, "result", "results", 0, "error_code")),
			set("another value for item 2", "batch-group-add-duplicate", "x", "result", "results", 2, "value"),
		),
		batchFact("K15 a user_mod batch answers success, NotFound, EmptyModlist and success, each item on its own; the item after the failures was applied",
			"batch-user-mod-mixed",
			[]item{{"user_mod", "", 0}, {"user_mod", "NotFound", 4001}, {"user_mod", "EmptyModlist", 4202}, {"user_mod", "", 0}},
			func(c *factCheck, s *captureSet, _ []BatchItem) {
				e, err := s.entry("user-show-after-batch")
				if c.noError(err) {
					c.that(slices.Equal(attr(e, "loginshell"), []string{"/bin/zsh"}), "the last item's change was not applied: %v", attr(e, "loginshell"))
				}
			},
			set("another error name for item 1", "batch-user-mod-mixed", "EmptyResult", "result", "results", 1, "error_name"),
			set("another code for item 2", "batch-user-mod-mixed", 4001, "result", "results", 2, "error_code"),
			set("the last change not applied", "user-show-after-batch", []any{"/bin/sh"}, entryPath("loginshell")...),
			set("a count that does not match", "batch-user-mod-mixed", 3, "result", "count"),
		),
		batchFact("K15 a delete batch answers each item: a deleted user and group are successes with their names, a missing one is NotFound",
			"batch-delete-mixed",
			[]item{{"user_del", "", 0}, {"user_del", "NotFound", 4001}, {"group_del", "", 0}, {"group_del", "NotFound", 4001}},
			func(c *factCheck, _ *captureSet, got []BatchItem) {
				for i, want := range map[int]string{0: "p24cap-bu1", 2: "p24cap-bgd"} {
					v := itemValue(c, got[i].Result, fmt.Sprintf("item %d", i))
					c.that(fmt.Sprint(v["value"]) == "["+want+"]", "item %d value = %v, want [%s]", i, v["value"], want)
				}
			},
			set("another error name for the missing user", "batch-delete-mixed", "EmptyResult", "result", "results", 1, "error_name"),
			set("another value for the deleted group", "batch-delete-mixed", []any{"p24cap-x"}, "result", "results", 2, "value"),
			set("a success for the missing group", "batch-delete-mixed", nil, "result", "results", 3, "error"),
		),
		{
			id: "K12/K13/K15 the member commands as batch items: each item carries its own completed and failed.member, an item for a missing group is NotFound, and every member is accounted for",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				bm1, bm2, nobody := "p24cap-bm1", "p24cap-bm2", "p24cap-nobody"
				cmds := []Command{
					memberCommand("group_add_member", "p24cap-mg3", "user", bm1),
					memberCommand("group_add_member", "p24cap-mg3", "user", bm2),
					memberCommand("group_add_member", "p24cap-nogroup", "user", bm2),
					memberCommand("group_remove_member", "p24cap-mg3", "user", bm1, bm2, nobody),
				}
				got, _, err := s.batch(t_, "batch-members-mixed", cmds...)
				if !c.noError(err) {
					return c.err()
				}
				type want struct {
					requested, completed int
					failed               []MemberFailure
				}
				for i, w := range map[int]want{
					0: {1, 0, []MemberFailure{{"user", bm1, "This entry is already a member"}}},
					1: {1, 1, nil},
					3: {3, 2, []MemberFailure{{"user", nobody, "This entry is not a member"}}},
				} {
					if got[i].Err != nil || got[i].Result == nil {
						c.that(false, "item %d: %+v, want a success", i, got[i].Err)
						continue
					}
					mr, err := DecodeMemberResult(got[i].Result, w.requested)
					if c.noError(err) {
						c.that(mr.Completed == w.completed && slices.Equal(mr.Failed, w.failed), "item %d: %+v, want completed %d failed %v", i, mr, w.completed, w.failed)
					}
				}
				c.that(got[2].Err != nil && got[2].Err.Name == "NotFound" && got[2].Err.Code == 4001, "item 2 = %+v", got[2].Err)
				return c.err()
			},
			probes: []probe{
				set("one more completed in item 3", "batch-members-mixed", 3, "result", "results", 3, "completed"),
				set("another reason in item 0", "batch-members-mixed", "x", "result", "results", 0, "failed", "member", "user", 0, 1),
				del("no failed.member in item 1", "batch-members-mixed", "result", "results", 1, "failed", "member"),
				set("item 2 not an error", "batch-members-mixed", nil, "result", "results", 2, "error_name"),
				both("a success item turned into an error item",
					set("error", "batch-members-mixed", "boom", "result", "results", 1, "error"),
					add("name", "batch-members-mixed", "NotFound", "result", "results", 1, "error_name"),
					add("code", "batch-members-mixed", 4001, "result", "results", 1, "error_code")),
				set("another code for item 2", "batch-members-mixed", 4031, "result", "results", 2, "error_code"),
			},
		},
		batchFact("K19 the pre-write re-read: a batch of user_show and group_show with all=true answers each item, a missing one is NotFound, and the others carry the same ipauniqueid as a single show",
			"batch-show-one-missing",
			[]item{{"user_show", "", 0}, {"user_show", "NotFound", 4001}, {"group_show", "", 0}, {"group_show", "NotFound", 4001}},
			func(c *factCheck, s *captureSet, got []BatchItem) {
				u := itemValue(c, got[0].Result, "item 0")
				ur, _ := u["result"].(map[string]any)
				single, err := s.entry("user-show-after-batch")
				if c.noError(err) {
					c.that(slices.Equal(attr(ur, "ipauniqueid"), attr(single, "ipauniqueid")) && len(attr(ur, "ipauniqueid")) == 1, "ipauniqueid in the batch %v, single %v", attr(ur, "ipauniqueid"), attr(single, "ipauniqueid"))
				}
				g := itemValue(c, got[2].Result, "item 2")
				gr, _ := g["result"].(map[string]any)
				c.that(len(attr(gr, "ipauniqueid")) == 1 && len(attr(gr, "gidnumber")) == 1, "the group item lacks ipauniqueid or gidnumber: %v", gr)
				// The same group read once more, after the batch, on its own (the only
				// other read of it): the batch item names the same object, not another
				// one with the same name.
				found := findEntryByName(s, "group-find-after-batch", "cn", "p24cap-bg")
				c.that(found != nil, "group-find-after-batch has no p24cap-bg")
				if found != nil {
					c.that(slices.Equal(attr(gr, "ipauniqueid"), attr(found, "ipauniqueid")), "ipauniqueid of the group in the batch %v, in the single read %v", attr(gr, "ipauniqueid"), attr(found, "ipauniqueid"))
					c.that(slices.Equal(attr(gr, "gidnumber"), attr(found, "gidnumber")), "gidnumber of the group in the batch %v, in the single read %v", attr(gr, "gidnumber"), attr(found, "gidnumber"))
				}
			},
			set("another error name for the missing user", "batch-show-one-missing", "EmptyResult", "result", "results", 1, "error_name"),
			set("another ipauniqueid in the batch", "batch-show-one-missing", []any{"00000000-0000-0000-0000-000000000000"}, "result", "results", 0, "result", "ipauniqueid"),
			del("no gidnumber for the group", "batch-show-one-missing", "result", "results", 2, "result", "gidnumber"),
			set("a success for the missing group", "batch-show-one-missing", nil, "result", "results", 3, "error"),
			set("another ipauniqueid for the group in the batch", "batch-show-one-missing", []any{"00000000-0000-0000-0000-000000000000"}, "result", "results", 2, "result", "ipauniqueid"),
			set("another ipauniqueid for the group in the single read", "group-find-after-batch", []any{"00000000-0000-0000-0000-000000000000"}, "result", "result", 2, "ipauniqueid"),
			set("another gidnumber for the group in the batch", "batch-show-one-missing", []any{"1"}, "result", "results", 2, "result", "gidnumber"),
			set("the group of the single read renamed", "group-find-after-batch", []any{"p24cap-other"}, "result", "result", 2, "cn"),
		),
	}
}

// K19
func factsReReads() []captureFact {
	return []captureFact{
		{
			id: "K19 a user_show lists the groups the user is directly in under memberof_group and the groups reached through another group under memberofindirect_group: the re-read's memberof_group is direct only",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				u, err := s.entry("user-show-before-member-group-del")
				if !c.noError(err) {
					return c.err()
				}
				c.that(sameSet(attr(u, "memberof_group"), []string{"ipausers", "p24cap-mdel"}), "memberof_group = %v, want the direct groups only", attr(u, "memberof_group"))
				c.that(slices.Equal(attr(u, "memberofindirect_group"), []string{"p24cap-mg1"}), "memberofindirect_group = %v", attr(u, "memberofindirect_group"))
				// The group view of the same state: p24cap-mg1 holds p24cap-mdel as
				// its member group and the user only as an indirect member, so it is
				// not a group the user is directly in.
				g, err := s.entry("group-show-before-member-group-del")
				if c.noError(err) {
					c.that(slices.Equal(attr(g, "cn"), []string{"p24cap-mg1"}) && slices.Equal(attr(g, "member_group"), []string{"p24cap-mdel"}), "the parent group is %v with member_group %v", attr(g, "cn"), attr(g, "member_group"))
					_, direct := g["member_user"]
					c.that(!direct && slices.Contains(attr(g, "memberindirect_user"), "p24cap-m1"), "the user is a direct member of the parent group: member_user %v, memberindirect_user %v", g["member_user"], attr(g, "memberindirect_user"))
					c.that(slices.Equal(attr(u, "uid"), []string{"p24cap-m1"}), "the user read is %v", attr(u, "uid"))
					c.that(!slices.Contains(attr(u, "memberof_group"), "p24cap-mg1"), "memberof_group lists the parent group p24cap-mg1, which is reached only through p24cap-mdel")
				}
				return c.err()
			},
			probes: []probe{
				set("the indirect group listed as direct (the shape of a transitive memberof_group)", "user-show-before-member-group-del", []any{"ipausers", "p24cap-mdel", "p24cap-mg1"}, entryPath("memberof_group")...),
				del("no indirect group listed", "user-show-before-member-group-del", entryPath("memberofindirect_group")...),
				set("another indirect group", "user-show-before-member-group-del", []any{"p24cap-x"}, entryPath("memberofindirect_group")...),
				set("the direct group missing", "user-show-before-member-group-del", []any{"ipausers"}, entryPath("memberof_group")...),
				add("the user a direct member of the parent group", "group-show-before-member-group-del", []any{"p24cap-m1"}, entryPath("member_user")...),
				set("the parent group renamed", "group-show-before-member-group-del", []any{"p24cap-other"}, entryPath("cn")...),
			},
		},
		{
			id: "K19 a user_show with all=true carries ipauniqueid (a uuid), uidnumber and gidnumber, nsaccountlock and preserved as booleans, and the password timestamps",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				for _, name := range []string{
					"user-show-no-password", "user-show-after-passwd", "user-show-after-passwd-again", "user-show-disabled", "user-show-preserved",
					"user-show-member", "user-show-after-batch", "user-show-after-passwd-maxlife0", "user-show-all-options",
				} {
					e, err := s.entry(name)
					if !c.noError(err) {
						continue
					}
					id := attr(e, "ipauniqueid")
					c.that(len(id) == 1 && uuidRe.MatchString(id[0]), "%s: ipauniqueid = %v", name, id)
					for _, k := range []string{"uidnumber", "gidnumber"} {
						v := attr(e, k)
						c.that(len(v) == 1 && regexp.MustCompile(`^[0-9]+$`).MatchString(v[0]), "%s: %s = %v", name, k, v)
					}
					_, isBoolLock := e["nsaccountlock"].(bool)
					_, isBoolPres := e["preserved"].(bool)
					c.that(isBoolLock && isBoolPres, "%s: nsaccountlock/preserved = %v/%v, want booleans", name, e["nsaccountlock"], e["preserved"])
				}
				d, err := s.entry("user-show-disabled")
				if c.noError(err) {
					c.that(d["nsaccountlock"] == true && d["preserved"] == false, "a disabled user: nsaccountlock %v preserved %v", d["nsaccountlock"], d["preserved"])
				}
				return c.err()
			},
			probes: []probe{
				del("no ipauniqueid", "user-show-after-passwd", entryPath("ipauniqueid")...),
				set("a text for nsaccountlock", "user-show-disabled", "TRUE", entryPath("nsaccountlock")...),
				set("a malformed uidnumber", "user-show-member", []any{"x"}, entryPath("uidnumber")...),
				set("an enabled user for the disabled one", "user-show-disabled", false, entryPath("nsaccountlock")...),
				del("no preserved flag", "user-show-no-password", entryPath("preserved")...),
			},
		},
		{
			id: "K19 a group_show with all=true separates the direct members (member_user, member_group) from the indirect (memberindirect_*), and a user_show lists the groups it is directly in; an empty group has no member attribute at all",
			run: func(_ testingT, s *captureSet) error {
				var c factCheck
				g, err := s.entry("group-show-members")
				if c.noError(err) {
					c.that(sameSet(attr(g, "member_user"), []string{"p24cap-m1", "p24cap-m2"}), "member_user = %v", attr(g, "member_user"))
					c.that(sameSet(attr(g, "member_group"), []string{"p24cap-mg2", "p24cap-mg3"}), "member_group = %v", attr(g, "member_group"))
					c.that(slices.Equal(attr(g, "memberindirect_user"), []string{"p24cap-m3"}), "memberindirect_user = %v: a user in a member group must be indirect", attr(g, "memberindirect_user"))
					c.that(len(attr(g, "ipauniqueid")) == 1 && len(attr(g, "gidnumber")) == 1, "group_show lacks ipauniqueid or gidnumber")
				}
				u, err := s.entry("user-show-member")
				if c.noError(err) {
					c.that(sameSet(attr(u, "memberof_group"), []string{"p24cap-mg1", "ipausers"}), "memberof_group = %v", attr(u, "memberof_group"))
				}
				for _, name := range []string{"group-show-after-empty-description", "group-show-marker"} {
					e, err := s.entry(name)
					if !c.noError(err) {
						continue
					}
					for _, k := range []string{"member_user", "member_group", "memberindirect_user", "memberindirect_group"} {
						_, has := e[k]
						c.that(!has, "%s carries %s though it has no members", name, k)
					}
				}
				return c.err()
			},
			probes: []probe{
				set("an indirect user listed as direct", "group-show-members", []any{"p24cap-m1", "p24cap-m2", "p24cap-m3"}, entryPath("member_user")...),
				del("no indirect members", "group-show-members", entryPath("memberindirect_user")...),
				set("another direct group", "group-show-members", []any{"p24cap-mg2"}, entryPath("member_group")...),
				set("the user in no group", "user-show-member", []any{"ipausers"}, entryPath("memberof_group")...),
				add("members on the empty group", "group-show-after-empty-description", []any{"p24cap-m1"}, entryPath("member_user")...),
				del("no ipauniqueid on the group", "group-show-members", entryPath("ipauniqueid")...),
				del("no gidnumber on the group", "group-show-members", entryPath("gidnumber")...),
			},
		},
	}
}

// K21
func factsEmptyValues() []captureFact {
	requirement := func(opt string) (string, int, string) { return "RequirementError", 3007, "'" + opt + "' is required" }
	homeless := `missing attribute "homeDirectory" required by object class "posixAccount"`
	var facts []captureFact
	for _, verb := range []string{"add", "mod"} {
		method := "user_" + verb
		for _, opt := range []string{"givenname", "sn", "homedirectory"} {
			fixture := "user-" + verb + "-empty-" + opt
			name, code, msg := requirement(opt)
			if opt == "homedirectory" {
				name, code, msg = "ObjectclassViolation", 4205, homeless
			}
			facts = append(facts, captureFact{
				id: fmt.Sprintf("K21 %s with %s=\"\" is refused: %s %d", method, opt, name, code),
				run: func(t_ testingT, s *captureSet) error {
					var c factCheck
					_, _, err := s.call(t_, fixture, Command{Method: method, Args: []any{"x"}, Options: map[string]any{opt: ""}})
					c.rpc(fixture, err, name, code, msg)
					return c.err()
				},
				probes: []probe{
					set("another name", fixture, "NotFound", "error", "name"),
					set("another code", fixture, 4001, "error", "code"),
					asSuccess("the empty value accepted", fixture),
				},
			})
		}
	}
	// The values FreeIPA accepts as empty leave the attribute out: they do not
	// fall back to the default.
	for _, opt := range []string{"loginshell", "displayname", "mail"} {
		addFixture, modFixture := "user-add-empty-"+opt, "user-mod-empty-"+opt
		defaults := map[string]string{"loginshell": "/bin/sh", "displayname": "P24 Empty", "mail": "p24cap-ue-mail@ipa.pilot.internal"}
		facts = append(facts, captureFact{
			id: fmt.Sprintf("K21 %s=\"\" is accepted by user_add and user_mod and leaves the attribute out (not the default %q)", opt, defaults[opt]),
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				for _, fixture := range []string{addFixture, modFixture} {
					method := "user_add"
					if fixture == modFixture {
						method = "user_mod"
					}
					_, _, err := s.call(t_, fixture, Command{Method: method, Args: []any{"x"}, Options: map[string]any{opt: ""}})
					if !c.noError(err) {
						continue
					}
					e, err := s.entry(fixture)
					if c.noError(err) {
						_, has := e[opt]
						c.that(!has, "%s: %s = %v, want the attribute left out", fixture, opt, e[opt])
						c.that(len(attr(e, "givenname")) == 1 && len(attr(e, "sn")) == 1, "%s: the other attributes are not there", fixture)
					}
				}
				return c.err()
			},
			probes: []probe{
				add("the attribute present on add", addFixture, []any{defaults[opt]}, entryPath(opt)...),
				add("the attribute present on mod", modFixture, []any{defaults[opt]}, entryPath(opt)...),
				asError("the empty value refused on mod", modFixture),
				del("no given name on add", addFixture, entryPath("givenname")...),
			},
		})
	}
	facts = append(facts,
		captureFact{
			id: "K21 after the empty mods the user keeps the names and home and has no shell, display name or mail; an empty list for mail clears it too",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				e, err := s.entry("user-show-after-empty-mods")
				if c.noError(err) {
					for _, k := range []string{"loginshell", "displayname", "mail"} {
						_, has := e[k]
						c.that(!has, "%s = %v after clearing it", k, e[k])
					}
					c.that(slices.Equal(attr(e, "givenname"), []string{"P24"}) && slices.Equal(attr(e, "homedirectory"), []string{"/srv/home/p24cap-ue"}), "givenname/homedirectory = %v/%v", attr(e, "givenname"), attr(e, "homedirectory"))
				}
				res, _, err := s.call(t_, "user-mod-empty-mail-list", Command{Method: "user_mod", Args: []any{"x"}, Options: map[string]any{"mail": []any{}}})
				c.noError(err)
				_ = res
				l, err := s.entry("user-show-after-empty-mail-list")
				if c.noError(err) {
					_, has := l["mail"]
					c.that(!has, "mail = %v after an empty list", l["mail"])
					c.that(len(attr(l, "loginshell")) == 1, "an empty mail list cleared the shell too")
				}
				return c.err()
			},
			probes: []probe{
				add("a shell left after clearing it", "user-show-after-empty-mods", []any{"/bin/sh"}, entryPath("loginshell")...),
				add("a mail left after clearing it", "user-show-after-empty-mods", []any{"x@example.test"}, entryPath("mail")...),
				add("a mail left after an empty list", "user-show-after-empty-mail-list", []any{"x@example.test"}, entryPath("mail")...),
				set("another given name after the empty mods", "user-show-after-empty-mods", []any{"x"}, entryPath("givenname")...),
				set("another home after the empty mods", "user-show-after-empty-mods", []any{"/home/x"}, entryPath("homedirectory")...),
				del("the shell cleared by the empty mail list", "user-show-after-empty-mail-list", entryPath("loginshell")...),
				asError("the empty mail list refused", "user-mod-empty-mail-list"),
			},
		},
		captureFact{
			id: "K21 a group_add or group_mod with description=\"\" succeeds and leaves the description out",
			run: func(t_ testingT, s *captureSet) error {
				var c factCheck
				for fixture, method := range map[string]string{"group-add-empty-description": "group_add", "group-mod-empty-description": "group_mod"} {
					_, _, err := s.call(t_, fixture, Command{Method: method, Args: []any{"x"}, Options: map[string]any{"description": ""}})
					if !c.noError(err) {
						continue
					}
					e, err := s.entry(fixture)
					if c.noError(err) {
						_, has := e["description"]
						c.that(!has, "%s: description = %v", fixture, e["description"])
					}
				}
				g, err := s.entry("group-show-after-empty-description")
				if c.noError(err) {
					_, has := g["description"]
					c.that(!has, "read back: description = %v", g["description"])
				}
				return c.err()
			},
			probes: []probe{
				add("a description on add", "group-add-empty-description", []any{""}, entryPath("description")...),
				add("a description on mod", "group-mod-empty-description", []any{"x"}, entryPath("description")...),
				add("a description read back", "group-show-after-empty-description", []any{"x"}, entryPath("description")...),
				asError("the empty description refused", "group-add-empty-description"),
			},
		},
	)
	return facts
}
