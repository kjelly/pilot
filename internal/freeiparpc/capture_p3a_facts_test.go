package freeiparpc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The facts of the P3a captures (capture_p3a_live_test.go): what the Go HBAC stage's
// design in docs/superpowers/specs/2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md
// rests on, with the K row of section 1.2 each belongs to. Every fact is checked
// against the committed fixtures, and again against the same set with one of the
// fixtures it reads replaced by an unrelated one, which it must reject (AGENTS.md
// section 5.12: a check that cannot fire proves nothing).

// p3aFixtures is what the harness writes, sorted.
var p3aFixtures = []string{
	"batch-hbac-mixed", "batch-hbac-show", "env-domain", "hbacrule-add-bare", "hbacrule-add-categories",
	"hbacrule-add-duplicate", "hbacrule-add-group", "hbacrule-add-group-already", "hbacrule-add-group-missing",
	"hbacrule-add-host", "hbacrule-add-host-already", "hbacrule-add-host-missing", "hbacrule-add-host-r5",
	"hbacrule-add-host-short-name", "hbacrule-add-host-upper-case", "hbacrule-add-host-while-hostcat-all",
	"hbacrule-add-hostgroup", "hbacrule-add-hostgroup-already", "hbacrule-add-hostgroup-missing",
	"hbacrule-add-hostgroup-while-hostcat-all", "hbacrule-add-lower-case-duplicate", "hbacrule-add-mixed-case",
	"hbacrule-add-service", "hbacrule-add-service-already", "hbacrule-add-service-missing",
	"hbacrule-add-service-r5", "hbacrule-add-service-while-servicecat-all",
	"hbacrule-add-two-users-one-already", "hbacrule-add-user", "hbacrule-add-user-already",
	"hbacrule-add-user-for-delete", "hbacrule-add-user-missing", "hbacrule-add-user-mixed-missing",
	"hbacrule-add-user-rule-not-found", "hbacrule-del", "hbacrule-del-not-found", "hbacrule-disable",
	"hbacrule-disable-allow-all", "hbacrule-disable-allow-all-again", "hbacrule-disable-already",
	"hbacrule-disable-breakglass", "hbacrule-disable-not-found", "hbacrule-enable", "hbacrule-enable-allow-all",
	"hbacrule-enable-allow-all-again", "hbacrule-enable-already", "hbacrule-enable-not-found",
	"hbacrule-find-builtin", "hbacrule-find-case", "hbacrule-mod-description",
	"hbacrule-mod-hostcat-all-with-hosts", "hbacrule-mod-hostcat-clear", "hbacrule-mod-hostcat-clear-again",
	"hbacrule-mod-no-change", "hbacrule-mod-no-options", "hbacrule-mod-not-found",
	"hbacrule-mod-servicecat-all-both", "hbacrule-mod-servicecat-all-with-services", "hbacrule-remove-group",
	"hbacrule-remove-host", "hbacrule-remove-hostgroup", "hbacrule-remove-service", "hbacrule-remove-user",
	"hbacrule-remove-user-missing", "hbacrule-remove-user-not-member", "hbacrule-show-after-member-user-del",
	"hbacrule-show-after-removals", "hbacrule-show-after-short-host", "hbacrule-show-all-members",
	"hbacrule-show-allow-all", "hbacrule-show-allow-all-disabled", "hbacrule-show-allow-all-enabled",
	"hbacrule-show-bare", "hbacrule-show-categories", "hbacrule-show-disabled", "hbacrule-show-enabled",
	"hbacrule-show-hostcat-cleared", "hbacrule-show-lower-case", "hbacrule-show-mixed-case",
	"hbacrule-show-not-found", "hbacsvc-add-duplicate", "hbacsvc-add-mixed-case", "hbacsvc-find-builtin",
	"hbacsvc-find-created", "hbacsvc-show-not-found", "hbacsvc-show-sshd", "hbactest-admin-granted",
	"hbactest-breakglass-disabled", "hbactest-breakglass-granted", "hbactest-denied", "hbactest-denied-user",
	"hbactest-granted", "hbactest-rules-option", "hbactest-target-host-missing", "host-find-pkey-only",
	"hostgroup-find-pkey-only", "user-del-while-on-rule",
}

type p3aFixture struct {
	status int
	body   map[string]any
}

type p3aSet map[string]p3aFixture

func loadP3aSet(t *testing.T, dir string) p3aSet {
	t.Helper()
	set := p3aSet{}
	for _, n := range p3aFixtures {
		raw, err := os.ReadFile(filepath.Join(dir, n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		st, err := os.ReadFile(filepath.Join(dir, n+".status"))
		if err != nil {
			t.Fatal(err)
		}
		var code int
		if _, err := fmt.Sscanf(string(st), "%d", &code); err != nil {
			t.Fatalf("%s.status: %v", n, err)
		}
		set[n] = p3aFixture{status: code, body: body}
	}
	return set
}

func (s p3aSet) clone() p3aSet {
	c := make(p3aSet, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

// result is the object a command answers with ("result" of "result" for a show, the
// answer of a member command, a boolean for enable and disable).
func (s p3aSet) result(name string) (map[string]any, error) {
	f, ok := s[name]
	if !ok {
		return nil, fmt.Errorf("no fixture %s", name)
	}
	if f.status != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", name, f.status)
	}
	r, _ := f.body["result"].(map[string]any)
	if r == nil {
		return nil, fmt.Errorf("%s: no result object (%v)", name, f.body["error"])
	}
	return r, nil
}

func (s p3aSet) entry(name string) (map[string]any, error) {
	r, err := s.result(name)
	if err != nil {
		return nil, err
	}
	e, _ := r["result"].(map[string]any)
	if e == nil {
		return nil, fmt.Errorf("%s: the answer has no entry", name)
	}
	return e, nil
}

// failure is the error a fixture answers with.
func (s p3aSet) failure(name string) (string, int, string, error) {
	f, ok := s[name]
	if !ok {
		return "", 0, "", fmt.Errorf("no fixture %s", name)
	}
	e, _ := f.body["error"].(map[string]any)
	if e == nil {
		return "", 0, "", fmt.Errorf("%s: the answer is not an error", name)
	}
	code, _ := e["code"].(float64)
	nm, _ := e["name"].(string)
	msg, _ := e["message"].(string)
	return nm, int(code), msg, nil
}

func strList(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func wantErr(s p3aSet, name, errName string, code int) error {
	got, c, _, err := s.failure(name)
	if err != nil {
		return err
	}
	if got != errName || c != code {
		return fmt.Errorf("%s answers %s (%d), want %s (%d)", name, got, c, errName, code)
	}
	return nil
}

// memberFailure is the text FreeIPA gives for one member of a member command's failed
// list, and how many members the command changed.
func memberFailure(s p3aSet, name, area, kind string) (completed float64, text string, err error) {
	r, err := s.result(name)
	if err != nil {
		return 0, "", err
	}
	completed, _ = r["completed"].(float64)
	failed, _ := r["failed"].(map[string]any)
	a, _ := failed[area].(map[string]any)
	l, _ := a[kind].([]any)
	if len(l) == 0 {
		return completed, "", nil
	}
	pair, _ := l[0].([]any)
	if len(pair) != 2 {
		return completed, "", fmt.Errorf("%s: a failed member is %v, want [name, text]", name, l[0])
	}
	text, _ = pair[1].(string)
	return completed, text, nil
}

type p3aFact struct {
	k     string // the K row of the spec
	what  string
	reads []string
	check func(s p3aSet) error
}

func p3aFacts() []p3aFact {
	flag := func(e map[string]any, want bool) bool {
		l, ok := e["ipaenabledflag"].([]any)
		if !ok || len(l) != 1 {
			return false
		}
		b, ok := l[0].(bool)
		return ok && b == want
	}
	memberText := func(name, area, kind, wantText string, wantCompleted float64) func(p3aSet) error {
		return func(s p3aSet) error {
			c, text, err := memberFailure(s, name, area, kind)
			if err != nil {
				return err
			}
			if text != wantText || c != wantCompleted {
				return fmt.Errorf("%s: completed %v, failed text %q; want %v and %q", name, c, text, wantCompleted, wantText)
			}
			return nil
		}
	}
	return []p3aFact{
		{"K1", "hbacrule_find lists the built-in rules; ipaenabledflag is a one-element list of a JSON boolean; the answer carries count and truncated", []string{"hbacrule-find-builtin"},
			func(s p3aSet) error {
				r, err := s.result("hbacrule-find-builtin")
				if err != nil {
					return err
				}
				entries, _ := r["result"].([]any)
				var names []string
				for _, x := range entries {
					e, _ := x.(map[string]any)
					cn, _ := strList(e["cn"])
					names = append(names, cn...)
					if !flag(e, true) {
						return fmt.Errorf("a built-in rule's ipaenabledflag is %v, want [true]", e["ipaenabledflag"])
					}
				}
				if !slices.Contains(names, "allow_all") || !slices.Contains(names, "allow_systemd-user") {
					return fmt.Errorf("the built-in rules are %v", names)
				}
				if _, ok := r["count"].(float64); !ok || r["truncated"] != false {
					return fmt.Errorf("count/truncated: %v %v", r["count"], r["truncated"])
				}
				return nil
			}},
		{"K1", "a show names the members by kind: memberuser_user, memberuser_group, memberhost_host (lower-case FQDN), memberhost_hostgroup, memberservice_hbacsvc", []string{"hbacrule-show-all-members"},
			func(s p3aSet) error {
				e, err := s.entry("hbacrule-show-all-members")
				if err != nil {
					return err
				}
				want := map[string][]string{
					"memberuser_user": {"p3acap-u1"}, "memberuser_group": {"p3acap-g1"},
					"memberhost_host": {"p3acap-h1.ipa.pilot.internal"}, "memberhost_hostgroup": {"p3acap-hg1"},
					"memberservice_hbacsvc": {"p3acap-svc1"},
				}
				for k, w := range want {
					got, ok := strList(e[k])
					if !ok || !slices.Equal(got, w) {
						return fmt.Errorf("%s is %v, want %v", k, e[k], w)
					}
				}
				return nil
			}},
		{"K1", "a rule without a category has no category key; a category is [\"all\"]; a built-in rule has user, host and service category all", []string{"hbacrule-show-bare", "hbacrule-show-categories", "hbacrule-show-allow-all-enabled"},
			func(s p3aSet) error {
				bare, err := s.entry("hbacrule-show-bare")
				if err != nil {
					return err
				}
				for _, k := range []string{"hostcategory", "servicecategory", "usercategory"} {
					if _, ok := bare[k]; ok {
						return fmt.Errorf("a rule without categories has %s", k)
					}
				}
				for _, n := range []string{"hbacrule-show-categories", "hbacrule-show-allow-all-enabled"} {
					e, err := s.entry(n)
					if err != nil {
						return err
					}
					for _, k := range []string{"hostcategory", "servicecategory"} {
						if got, _ := strList(e[k]); !slices.Equal(got, []string{"all"}) {
							return fmt.Errorf("%s: %s is %v", n, k, e[k])
						}
					}
				}
				e, _ := s.entry("hbacrule-show-allow-all-enabled")
				if got, _ := strList(e["usercategory"]); !slices.Equal(got, []string{"all"}) {
					return fmt.Errorf("allow_all usercategory is %v", e["usercategory"])
				}
				return nil
			}},
		{"K2", "a duplicate is DuplicateEntry 4002, a missing object is NotFound 4001, a modification with no change is EmptyModlist 4202", []string{"hbacrule-add-duplicate", "hbacsvc-add-duplicate", "hbacrule-del-not-found", "hbacrule-show-not-found", "hbacrule-mod-no-change", "hbacrule-mod-no-options", "hbacrule-mod-hostcat-clear-again", "hbacrule-enable-not-found"},
			func(s p3aSet) error {
				for name, w := range map[string][2]any{
					"hbacrule-add-duplicate": {"DuplicateEntry", 4002}, "hbacsvc-add-duplicate": {"DuplicateEntry", 4002},
					"hbacrule-del-not-found": {"NotFound", 4001}, "hbacrule-show-not-found": {"NotFound", 4001},
					"hbacrule-enable-not-found": {"NotFound", 4001},
					"hbacrule-mod-no-change":    {"EmptyModlist", 4202}, "hbacrule-mod-no-options": {"EmptyModlist", 4202},
					"hbacrule-mod-hostcat-clear-again": {"EmptyModlist", 4202},
				} {
					if err := wantErr(s, name, w[0].(string), w[1].(int)); err != nil {
						return err
					}
				}
				return nil
			}},
		{"K2", "a member command answers HTTP 200 with completed and a failed list per kind: added is completed 1; already there is completed 0 with \"This entry is already a member\"; an object that does not exist is \"no such entry\"", []string{"hbacrule-add-user", "hbacrule-add-user-already", "hbacrule-add-user-missing", "hbacrule-add-host-missing", "hbacrule-add-hostgroup-missing", "hbacrule-add-service-missing", "hbacrule-add-group-missing"},
			func(s p3aSet) error {
				for _, c := range []struct {
					name, area, kind, text string
					done                   float64
				}{
					{"hbacrule-add-user", "memberuser", "user", "", 1},
					{"hbacrule-add-user-already", "memberuser", "user", "This entry is already a member", 0},
					{"hbacrule-add-user-missing", "memberuser", "user", "no such entry", 0},
					{"hbacrule-add-group-missing", "memberuser", "group", "no such entry", 0},
					{"hbacrule-add-host-missing", "memberhost", "host", "no such entry", 0},
					{"hbacrule-add-hostgroup-missing", "memberhost", "hostgroup", "no such entry", 0},
					{"hbacrule-add-service-missing", "memberservice", "hbacsvc", "no such entry", 0},
				} {
					if err := memberText(c.name, c.area, c.kind, c.text, c.done)(s); err != nil {
						return err
					}
				}
				return nil
			}},
		{"K2", "removing a member that is not on the rule, or that does not exist, is completed 0 with \"This entry is not a member\" (not an error)", []string{"hbacrule-remove-user-not-member", "hbacrule-remove-user-missing", "hbacrule-remove-user"},
			func(s p3aSet) error {
				if err := memberText("hbacrule-remove-user-not-member", "memberuser", "user", "This entry is not a member", 0)(s); err != nil {
					return err
				}
				if err := memberText("hbacrule-remove-user-missing", "memberuser", "user", "This entry is not a member", 0)(s); err != nil {
					return err
				}
				return memberText("hbacrule-remove-user", "memberuser", "user", "", 1)(s)
			}},
		{"K2", "one call with two members, one already there, changes the other and lists the first", []string{"hbacrule-add-two-users-one-already"},
			memberText("hbacrule-add-two-users-one-already", "memberuser", "user", "This entry is already a member", 1)},
		{"K2", "enable and disable of a rule that is already in that state succeed and answer like a change", []string{"hbacrule-enable-already", "hbacrule-disable-already", "hbacrule-disable", "hbacrule-enable"},
			func(s p3aSet) error {
				for name, w := range map[string]string{
					"hbacrule-enable-already": "Enabled HBAC rule", "hbacrule-enable": "Enabled HBAC rule",
					"hbacrule-disable-already": "Disabled HBAC rule", "hbacrule-disable": "Disabled HBAC rule",
				} {
					r, err := s.result(name)
					if err != nil {
						return err
					}
					if r["result"] != true {
						return fmt.Errorf("%s: result is %v", name, r["result"])
					}
					if sum, _ := r["summary"].(string); !strings.HasPrefix(sum, w) {
						return fmt.Errorf("%s: summary %q, want it to start with %q", name, sum, w)
					}
				}
				return nil
			}},
		{"K2", "a rule's enabled state is read from ipaenabledflag; hbacrule_del answers with an empty failed list and the name", []string{"hbacrule-show-enabled", "hbacrule-show-disabled", "hbacrule-del"},
			func(s p3aSet) error {
				if e, err := s.entry("hbacrule-show-enabled"); err != nil || !flag(e, true) {
					return fmt.Errorf("an enabled rule: %v %v", e, err)
				}
				if e, err := s.entry("hbacrule-show-disabled"); err != nil || !flag(e, false) {
					return fmt.Errorf("a disabled rule: %v %v", e, err)
				}
				r, err := s.result("hbacrule-del")
				if err != nil {
					return err
				}
				inner, _ := r["result"].(map[string]any)
				if failed, ok := inner["failed"].([]any); !ok || len(failed) != 0 || len(inner) != 1 {
					return fmt.Errorf("hbacrule_del result is %v, want only an empty failed list", r["result"])
				}
				if v, _ := strList(r["value"]); !slices.Equal(v, []string{"p3acap-r2"}) {
					return fmt.Errorf("hbacrule_del value is %v", r["value"])
				}
				return nil
			}},
		{"K3", "a category and members exclude each other, in both directions, as MutuallyExclusiveError 4303", []string{"hbacrule-add-host-while-hostcat-all", "hbacrule-add-hostgroup-while-hostcat-all", "hbacrule-add-service-while-servicecat-all", "hbacrule-mod-hostcat-all-with-hosts", "hbacrule-mod-servicecat-all-with-services"},
			func(s p3aSet) error {
				for name, w := range map[string]string{
					"hbacrule-add-host-while-hostcat-all":       "hosts cannot be added when host category='all'",
					"hbacrule-add-hostgroup-while-hostcat-all":  "hosts cannot be added when host category='all'",
					"hbacrule-mod-hostcat-all-with-hosts":       "host category cannot be set to 'all' while there are allowed hosts",
					"hbacrule-add-service-while-servicecat-all": "",
					"hbacrule-mod-servicecat-all-with-services": "",
				} {
					nm, code, msg, err := s.failure(name)
					if err != nil {
						return err
					}
					if nm != "MutuallyExclusiveError" || code != 4303 || (w != "" && msg != w) {
						return fmt.Errorf("%s: %s %d %q", name, nm, code, msg)
					}
				}
				return nil
			}},
		{"K3", "an empty category value clears the category (the key is gone afterwards); clearing it again is EmptyModlist", []string{"hbacrule-mod-hostcat-clear", "hbacrule-show-hostcat-cleared"},
			func(s p3aSet) error {
				f := s["hbacrule-mod-hostcat-clear"]
				if f.status != 200 || f.body["error"] != nil {
					return fmt.Errorf("clearing the category: %v", f.body)
				}
				e, err := s.entry("hbacrule-show-hostcat-cleared")
				if err != nil {
					return err
				}
				if _, ok := e["hostcategory"]; ok {
					return fmt.Errorf("the cleared category is still there: %v", e["hostcategory"])
				}
				return nil
			}},
		{"K4", "a short host name is completed with the server's domain and stored as a lower-case FQDN; an upper-case FQDN is the same member", []string{"hbacrule-show-after-short-host", "hbacrule-add-host-upper-case", "env-domain"},
			func(s p3aSet) error {
				env, err := s.entry("env-domain")
				if err == nil {
					env, err = s.result("env-domain")
				}
				if err != nil {
					return err
				}
				domain, _ := env["result"].(map[string]any)["domain"].(string)
				if domain == "" {
					return fmt.Errorf("env has no domain: %v", env)
				}
				e, err := s.entry("hbacrule-show-after-short-host")
				if err != nil {
					return err
				}
				hosts, _ := strList(e["memberhost_host"])
				if !slices.Contains(hosts, "p3acap-h2."+domain) {
					return fmt.Errorf("the short name was stored as %v, want p3acap-h2.%s", hosts, domain)
				}
				return memberText("hbacrule-add-host-upper-case", "memberhost", "host", "This entry is already a member", 0)(s)
			}},
		{"K5", "hbactest answers value true or false, summary \"Access granted: ...\", matched null when nothing matched; with allow_all disabled admin is granted only by an enabled break-glass rule", []string{"hbactest-breakglass-granted", "hbactest-breakglass-disabled", "hbactest-admin-granted"},
			func(s p3aSet) error {
				for name, w := range map[string]bool{
					"hbactest-breakglass-granted": true, "hbactest-breakglass-disabled": false, "hbactest-admin-granted": false,
				} {
					r, err := s.result(name)
					if err != nil {
						return err
					}
					if r["value"] != w || r["summary"] != fmt.Sprintf("Access granted: %s", map[bool]string{true: "True", false: "False"}[w]) || r["error"] != nil {
						return fmt.Errorf("%s: value %v summary %v error %v", name, r["value"], r["summary"], r["error"])
					}
					if _, matched := r["matched"].([]any); matched != w {
						return fmt.Errorf("%s: matched is %v with access %v", name, r["matched"], w)
					}
				}
				return nil
			}},
		{"K6", "allow_all disabled shows ipaenabledflag [false] and enabling it again succeeds; disabling a disabled rule succeeds", []string{"hbacrule-show-allow-all-disabled", "hbacrule-disable-allow-all", "hbacrule-disable-allow-all-again", "hbacrule-enable-allow-all", "hbacrule-enable-allow-all-again"},
			func(s p3aSet) error {
				if e, err := s.entry("hbacrule-show-allow-all-disabled"); err != nil || !flag(e, false) {
					return fmt.Errorf("allow_all disabled: %v %v", e, err)
				}
				for _, n := range []string{"hbacrule-disable-allow-all", "hbacrule-disable-allow-all-again", "hbacrule-enable-allow-all", "hbacrule-enable-allow-all-again"} {
					if r, err := s.result(n); err != nil || r["result"] != true {
						return fmt.Errorf("%s: %v %v", n, r, err)
					}
				}
				return nil
			}},
		{"K7", "a rule's name is case-insensitive and keeps the spelling it was created with", []string{"hbacrule-add-lower-case-duplicate", "hbacrule-show-lower-case", "hbacrule-show-mixed-case"},
			func(s p3aSet) error {
				if err := wantErr(s, "hbacrule-add-lower-case-duplicate", "DuplicateEntry", 4002); err != nil {
					return err
				}
				for _, n := range []string{"hbacrule-show-lower-case", "hbacrule-show-mixed-case"} {
					e, err := s.entry(n)
					if err != nil {
						return err
					}
					if cn, _ := strList(e["cn"]); !slices.Equal(cn, []string{"P3aCap-CaseRule"}) {
						return fmt.Errorf("%s: cn is %v", n, e["cn"])
					}
				}
				return nil
			}},
		{"K8", "deleting a user removes it from the rules that name it, so the reference is gone, not dangling", []string{"hbacrule-show-after-member-user-del"},
			func(s p3aSet) error {
				e, err := s.entry("hbacrule-show-after-member-user-del")
				if err != nil {
					return err
				}
				if u, _ := strList(e["memberuser_user"]); !slices.Equal(u, []string{"p3acap-u1"}) {
					return fmt.Errorf("the rule's users are %v, want only p3acap-u1", e["memberuser_user"])
				}
				return nil
			}},
		{"K8", "a member command on a rule that does not exist is NotFound, not a failed list", []string{"hbacrule-add-user-rule-not-found", "hbacrule-mod-not-found"},
			func(s p3aSet) error {
				for _, n := range []string{"hbacrule-add-user-rule-not-found", "hbacrule-mod-not-found"} {
					if err := wantErr(s, n, "NotFound", 4001); err != nil {
						return err
					}
				}
				return nil
			}},
		{"K9", "a batch of HBAC writes answers one item per command, in order, with the failed list of a member command inside its item", []string{"batch-hbac-mixed"},
			func(s p3aSet) error {
				r, err := s.result("batch-hbac-mixed")
				if err != nil {
					return err
				}
				items, _ := r["results"].([]any)
				if len(items) != 4 {
					return fmt.Errorf("%d items, want 4", len(items))
				}
				third, _ := items[2].(map[string]any)
				if c, _ := third["completed"].(float64); c != 0 || third["failed"] == nil {
					return fmt.Errorf("the item of the member that does not exist is %v", third)
				}
				return nil
			}},
	}
}

func TestP3aCaptureFilesAreTheHarnessList(t *testing.T) {
	if !slices.IsSorted(p3aFixtures) || len(slices.Compact(slices.Clone(p3aFixtures))) != len(p3aFixtures) {
		t.Error("p3aFixtures is not sorted and free of repeats")
	}
	names := captureNames(t, "testdata")
	for _, n := range p3aFixtures {
		if !slices.Contains(names, n) {
			t.Errorf("%s is in the harness list but has no fixture", n)
		}
	}
	for _, n := range names {
		if strings.HasPrefix(n, "hbac") || strings.HasPrefix(n, "batch-hbac") || n == "env-domain" {
			if !slices.Contains(p3aFixtures, n) {
				t.Errorf("%s is a P3a-looking fixture the harness list does not have", n)
			}
		}
	}
	// The harness writes the constant .headers file next to each fixture, as the earlier
	// captures have; the P3a ones are not committed (the pull request would pass GitHub's
	// 300-file compare limit, kjelly/pilot#314), and nothing here reads them.
	for _, n := range p3aFixtures {
		if _, err := os.Stat(filepath.Join("testdata", n+".headers")); err == nil {
			t.Errorf("%s.headers is committed; the P3a fixtures keep only .json and .status", n)
		}
	}
}

func TestP3aCaptureFacts(t *testing.T) {
	set := loadP3aSet(t, "testdata")
	read := map[string]bool{}
	for _, f := range p3aFacts() {
		for _, n := range f.reads {
			read[n] = true
		}
		if err := f.check(set); err != nil {
			t.Errorf("%s: %s: %v", f.k, f.what, err)
		}
	}
	var unread []string
	for _, n := range p3aFixtures {
		if !read[n] {
			unread = append(unread, n)
		}
	}
	// A fixture no fact reads is kept for the tests that parse it (the reader and the
	// planner of P3-1); it is listed here so adding one is a decision.
	t.Logf("fixtures no fact reads: %d", len(unread))
}

// Each fact fires: with one of the fixtures it reads replaced by an unrelated one (an
// error answer, or a success that is not what the fact is about), the fact rejects the
// set. Two replacements are tried because a fact about an error is not moved by another
// error of the same name, and a fact about a success is not moved by another success.
func TestP3aCaptureFactsFire(t *testing.T) {
	set := loadP3aSet(t, "testdata")
	for _, f := range p3aFacts() {
		for _, n := range f.reads {
			fired := false
			for _, swap := range []string{"hbacrule-del-not-found", "hbacrule-add-bare", "env-domain"} {
				if swap == n {
					continue
				}
				broken := set.clone()
				broken[n] = set[swap]
				if f.check(broken) != nil {
					fired = true
					break
				}
			}
			if !fired {
				t.Errorf("%s: %s: still passes with %s replaced by each unrelated fixture", f.k, f.what, n)
			}
		}
	}
}
