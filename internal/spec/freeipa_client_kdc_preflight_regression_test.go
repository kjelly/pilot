package spec

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// GitHub issue #168: a host whose resolver cannot look up the KDC names in
// /etc/krb5.conf failed the freeipa-client --check preview at the no_log
// admin kinit of the host annotations / access policy reconcile, with a
// censored message, and the /etc/hosts pin that repairs the names is a
// mutation --check never writes. These tests lock the two shared task files
// that fix it:
//
//   - tasks/freeipa-client-kdc-preflight.yml (read-only name resolution
//     probe + ok/deferred/failed decision), and
//   - tasks/freeipa-client-kinit-result.yml (kinit failure classification
//     with the raw stderr withheld),
//
// and their wiring into the two callers. The probe script and the state
// machine are run for real (python3, ansible-playbook on localhost); the
// kinit stderr fixtures are in testdata/kinit-failures (live MIT krb5 1.22.2
// captures, plus clearly marked libkrb5 error-table text for the situations
// that could not be reproduced locally); resolvectl output fixtures are in
// testdata/kdc-preflight.

const (
	kdcPreflightPath  = "../../playbooks/apply/tasks/freeipa-client-kdc-preflight.yml"
	kinitResultPath   = "../../playbooks/apply/tasks/freeipa-client-kinit-result.yml"
	kdcPreflightProbe = "FreeIPA KDC preflight — resolve the KDC and FreeIPA server names with this host's own resolver (read-only)"
)

func requireAnsibleForKDCTests(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

func requirePython3ForKDCTests(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required python3 not installed: %v", err)
		}
		t.Skipf("python3 not installed: %v", err)
	}
	return p
}

// kdcPreflightScript returns the probe script embedded in the task's vars.
func kdcPreflightScript(t *testing.T) string {
	t.Helper()
	task := findNamedTask(t, loadYAML(t, kdcPreflightPath), kdcPreflightProbe)
	vars, _ := task["vars"].(map[string]any)
	script, _ := vars["freeipa_client_kdc_preflight_script"].(string)
	if script == "" {
		t.Fatal("probe task has no freeipa_client_kdc_preflight_script var")
	}
	return script
}

type kdcProbeResult struct {
	Names              []string          `json:"names"`
	KDCNames           []string          `json:"kdc_names"`
	Resolved           []string          `json:"resolved"`
	Unresolved         []string          `json:"unresolved"`
	Errors             map[string]string `json:"errors"`
	RequiredUnresolved []string          `json:"required_unresolved"`
	KDCUnusable        bool              `json:"kdc_unusable"`
	AdminUnresolved    []string          `json:"admin_unresolved"`
	Unparsable         []string          `json:"unparsable"`
	Nameservers        []string          `json:"nameservers"`
	Krb5Files          []string          `json:"krb5_files"`
}

func runKDCProbe(t *testing.T, input map[string]any) kdcProbeResult {
	t.Helper()
	py := requirePython3ForKDCTests(t)
	in, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(py, "-I", "-c", kdcPreflightScript(t), string(in))
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("probe script: %v\nstderr: %s", err, stderr.String())
	}
	var res kdcProbeResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("probe output is not JSON: %v\n%s", err, stdout.String())
	}
	return res
}

func writeKDCFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// krb5Realm renders a krb5.conf whose IPA.PILOT.INTERNAL realm stanza has the
// given relation lines.
func krb5Realm(relations ...string) string {
	return "[libdefaults]\n default_realm = IPA.PILOT.INTERNAL\n dns_lookup_kdc = false\n\n[realms]\n IPA.PILOT.INTERNAL = {\n  " +
		strings.Join(relations, "\n  ") + "\n  pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem\n }\n"
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestRegression_KDCPreflightScript runs the real probe with real python3
// and the real libc resolver: names that resolve (localhost, answered from
// /etc/hosts) must pass, names under .invalid (RFC 6761, never resolvable)
// must trigger, and the krb5.conf parsing must handle ports, brackets, IP
// literals, includedir layouts and other realms' stanzas.
func TestRegression_KDCPreflightScript(t *testing.T) {
	requirePython3ForKDCTests(t)
	const bad1, bad2 = "ipa1.pilot168.invalid", "ipa2.pilot168.invalid"

	t.Run("resolvable KDC passes", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = localhost:88", "master_kdc = localhost:88", "admin_server = localhost:749"))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if len(res.Unresolved) != 0 || len(res.RequiredUnresolved) != 0 {
			t.Fatalf("localhost must resolve: %+v", res)
		}
		if !sameSet(res.Names, []string{"localhost"}) || !sameSet(res.KDCNames, []string{"localhost"}) {
			t.Fatalf("port must be stripped and names de-duplicated: names=%v kdc=%v", res.Names, res.KDCNames)
		}
	})

	t.Run("unresolvable KDC triggers and is required", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = "+bad1+":88", "master_kdc = "+bad1+":88", "admin_server = "+bad1+":749"))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.Unresolved, []string{bad1}) || !sameSet(res.RequiredUnresolved, []string{bad1}) {
			t.Fatalf("want %s unresolved and required: %+v", bad1, res)
		}
		if res.Errors[bad1] == "" {
			t.Errorf("the resolver error for %s must be reported: %+v", bad1, res.Errors)
		}
	})

	t.Run("mixed: one KDC resolves, a stale one does not, so nothing is required", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = localhost:88", "kdc = "+bad2+":88"))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.Unresolved, []string{bad2}) {
			t.Fatalf("the stale KDC must be reported as unresolved: %+v", res)
		}
		if len(res.RequiredUnresolved) != 0 {
			t.Fatalf("kinit works when any KDC resolves; the stale name must not be required: %+v", res)
		}
	})

	t.Run("an IP literal KDC is skipped and keeps unresolvable names optional", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = 192.0.2.10:88", "kdc = [2001:db8::10]:88", "kdc = "+bad1))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.Names, []string{bad1}) {
			t.Fatalf("IP literals must not be probed as names: %v", res.Names)
		}
		if len(res.RequiredUnresolved) != 0 {
			t.Fatalf("an IP-literal KDC needs no resolution, so the name is optional: %+v", res)
		}
	})

	t.Run("krb5.conf.d realm file (EL layout) and includedir", func(t *testing.T) {
		dir := t.TempDir()
		confd := filepath.Join(dir, "krb5.conf.d")
		writeKDCFile(t, dir, "krb5.conf", "includedir "+confd+"\n[libdefaults]\n default_realm = IPA.PILOT.INTERNAL\n")
		writeKDCFile(t, confd, "freeipa-realm", "[realms]\n IPA.PILOT.INTERNAL = {\n  kdc = "+bad1+":88\n }\n")
		writeKDCFile(t, confd, "ignored.bak~", "[realms]\n IPA.PILOT.INTERNAL = {\n  kdc = "+bad2+":88\n }\n")
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{filepath.Join(dir, "krb5.conf")}, "resolvectl": ""})
		if !sameSet(res.RequiredUnresolved, []string{bad1}) {
			t.Fatalf("the realm stanza in the includedir file must be read (and the .bak~ file skipped): %+v", res)
		}
	})

	t.Run("another realm's stanza is ignored", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", "[realms]\n OTHER.REALM = {\n  kdc = "+bad1+":88\n }\n IPA.PILOT.INTERNAL = {\n  kdc = localhost\n }\n")
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.Names, []string{"localhost"}) {
			t.Fatalf("only the requested realm counts: %v", res.Names)
		}
	})

	t.Run("KKDCP URL host is taken from the URL", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = https://"+bad1+"/KdcProxy"))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.Names, []string{bad1}) {
			t.Fatalf("names = %v, want the URL host", res.Names)
		}
	})

	t.Run("admin endpoint FQDN is required even when a KDC resolves", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeKDCFile(t, dir, "krb5.conf", krb5Realm("kdc = localhost:88"))
		res := runKDCProbe(t, map[string]any{
			"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": "",
			"required_names": []string{"IPA1.Pilot168.invalid."}, "extra_names": []string{bad2},
		})
		if !sameSet(res.RequiredUnresolved, []string{bad1}) {
			t.Fatalf("the admin endpoint (normalised to lower case, trailing dot dropped) is required: %+v", res)
		}
		if !sameSet(res.Unresolved, []string{bad1, bad2}) {
			t.Fatalf("pool names are reported but not required: %+v", res)
		}
	})

	t.Run("no krb5.conf at all: nothing from krb5, only the supplied names", func(t *testing.T) {
		res := runKDCProbe(t, map[string]any{
			"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{filepath.Join(t.TempDir(), "absent")}, "resolvectl": "",
			"extra_names": []string{"localhost"},
		})
		if len(res.Unresolved) != 0 || !sameSet(res.Names, []string{"localhost"}) {
			t.Fatalf("%+v", res)
		}
	})

	t.Run("nameservers: resolv.conf plus resolvectl, stub dropped when resolvectl answered", func(t *testing.T) {
		dir := t.TempDir()
		resolv := writeKDCFile(t, dir, "resolv.conf", "# generated\nnameserver 127.0.0.53\noptions edns0\n")
		for _, tc := range []struct {
			fixture string
			want    []string
		}{
			{"resolvectl-dns-live.txt", []string{"192.168.100.254", "10.1.24.1"}},
			{"resolvectl-dns-issue168.txt", []string{"10.1.58.11", "1.1.1.1", "8.8.8.8"}},
		} {
			cat, _ := filepath.Abs(filepath.Join("testdata", "kdc-preflight", tc.fixture))
			abs := writeKDCFile(t, dir, "resolvectl-"+tc.fixture+".sh", "#!/bin/sh\ncat "+cat+"\n")
			if err := os.Chmod(abs, 0o755); err != nil {
				t.Fatal(err)
			}
			res := runKDCProbe(t, map[string]any{"realm": "R", "krb5_paths": []string{}, "resolv_conf": resolv, "resolvectl": abs})
			if strings.Join(res.Nameservers, " ") != strings.Join(tc.want, " ") {
				t.Errorf("%s: nameservers = %v, want %v", tc.fixture, res.Nameservers, tc.want)
			}
		}
		// Without resolvectl the stub is all there is: report it.
		res := runKDCProbe(t, map[string]any{"realm": "R", "krb5_paths": []string{}, "resolv_conf": resolv, "resolvectl": ""})
		if strings.Join(res.Nameservers, " ") != "127.0.0.53" {
			t.Errorf("without resolvectl: %v", res.Nameservers)
		}
		// A missing tool and a missing file only shorten the list.
		res = runKDCProbe(t, map[string]any{"realm": "R", "krb5_paths": []string{}, "resolv_conf": filepath.Join(dir, "none"), "resolvectl": "/nonexistent/resolvectl"})
		if len(res.Nameservers) != 0 {
			t.Errorf("nameservers = %v, want none", res.Nameservers)
		}
	})
}

// kdcPlay runs the real preflight task file once on localhost and returns the
// combined output and whether ansible-playbook succeeded.
type kdcPlay struct {
	check      bool
	krb5Conf   string
	pool       []string
	admin      string
	pin        any // nil: the pin register is absent (--tags run)
	resolvConf string
}

func (p kdcPlay) run(t *testing.T) (string, bool) {
	t.Helper()
	requireAnsibleForKDCTests(t)
	dir := t.TempDir()
	preflightAbs, _ := filepath.Abs(kdcPreflightPath)
	vars := map[string]any{
		"ipa_realm":                                "IPA.PILOT.INTERNAL",
		"ipa_client_fqdn":                          "client.pilot168.invalid",
		"freeipa_admin_server_fqdn":                p.admin,
		"freeipa_server_fqdns":                     p.pool,
		"freeipa_client_kdc_preflight_krb5_paths":  []string{p.krb5Conf},
		"freeipa_client_kdc_preflight_resolv_conf": p.resolvConf,
		"freeipa_client_kdc_preflight_resolvectl":  "",
	}
	if p.pin != nil {
		vars["freeipa_client_hosts_pool_pin"] = p.pin
	}
	play := []map[string]any{{
		"name": "preflight", "hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": vars,
		"tasks": []any{
			map[string]any{
				"ansible.builtin.include_tasks": map[string]any{"file": preflightAbs},
				"vars":                          map[string]any{"freeipa_client_kdc_preflight_caller": "FreeIPA host annotations"},
			},
			map[string]any{"ansible.builtin.debug": map[string]any{"msg": "PREFLIGHT_STATE={{ freeipa_client_kdc_preflight_state }} REASON={{ freeipa_client_kdc_preflight_reason }}"}},
		},
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-i", "localhost,", path}
	if p.check {
		args = append(args, "--check")
	}
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestRegression_KDCPreflightStateMachine runs the real task file through
// ansible-playbook and checks every cell that matters of
// {check mode} x {pin repair pending} x {pin covers the unresolved names}.
// `deferred` must happen only in check mode with a pending pin covering
// everything unresolved; every other unresolved cell must FAIL with a message
// naming the host, the FQDN and the resolver, and never be censored.
func TestRegression_KDCPreflightStateMachine(t *testing.T) {
	requireAnsibleForKDCTests(t)
	requirePython3ForKDCTests(t)
	const bad = "ipa1.pilot168.invalid"
	dir := t.TempDir()
	badConf := writeKDCFile(t, dir, "bad.conf", krb5Realm("kdc = "+bad+":88"))
	goodConf := writeKDCFile(t, dir, "good.conf", krb5Realm("kdc = localhost:88"))
	staleConf := writeKDCFile(t, dir, "stale.conf", krb5Realm("kdc = localhost:88", "kdc = ipa9.pilot168.invalid:88"))
	// The issue #168 follow-up (P2 findings of PR #180 review): a host whose
	// krb5.conf still lists a RETIRED KDC next to the active one.
	const active, retired = "active.pilot168.invalid", "retired.pilot168.invalid"
	activeRetiredConf := writeKDCFile(t, dir, "active-retired.conf", krb5Realm("kdc = "+active+":88", "kdc = "+retired+":88"))
	retiredOnlyConf := writeKDCFile(t, dir, "retired-only.conf", krb5Realm("kdc = "+retired+":88"))
	quotedLocalConf := writeKDCFile(t, dir, "quoted-local.conf", krb5Realm(`kdc = "localhost:88"`))
	plainLocalConf := writeKDCFile(t, dir, "plain-local.conf", krb5Realm("kdc = localhost:88"))
	quotedActiveConf := writeKDCFile(t, dir, "quoted-active.conf", krb5Realm(`kdc = "`+active+`:88"`))
	resolv := writeKDCFile(t, dir, "resolv.conf", "nameserver 192.0.2.53\nnameserver 1.1.1.1\n")

	pending := map[string]any{"changed": true}
	notPending := map[string]any{"changed": false}

	type cell struct {
		name      string
		play      kdcPlay
		wantOK    bool
		wantState string
		wantReas  string
		mustHave  []string
		mustNot   []string
	}
	cells := []cell{
		{name: "check, pin pending, covered: deferred", play: kdcPlay{check: true, krb5Conf: badConf, pool: []string{bad}, admin: bad, pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "deferred", wantReas: "pin_pending",
			mustHave: []string{"FreeIPA host annotations deferred to apply", "localhost cannot resolve " + bad, "resolver: 192.0.2.53, 1.1.1.1", "pin"}},
		{name: "real run, pin pending, covered: fails, never defers", play: kdcPlay{check: false, krb5Conf: badConf, pool: []string{bad}, admin: bad, pin: pending, resolvConf: resolv},
			wantReas: "unresolved_after_pin",
			mustHave: []string{"localhost cannot resolve " + bad, "resolver: 192.0.2.53, 1.1.1.1", "kinit would fail before it reached any KDC", "the resolver and /etc/nsswitch.conf hosts: are the cause"}},
		{name: "real run, pin not pending, covered: fails", play: kdcPlay{check: false, krb5Conf: badConf, pool: []string{bad}, admin: bad, pin: notPending, resolvConf: resolv},
			wantReas: "unresolved_after_pin", mustHave: []string{"localhost cannot resolve " + bad}},
		{name: "check, pin not pending, covered: fails", play: kdcPlay{check: true, krb5Conf: badConf, pool: []string{bad}, admin: bad, pin: notPending, resolvConf: resolv},
			wantReas: "no_pending_pin", mustHave: []string{"localhost cannot resolve " + bad, "no pending /etc/hosts server-pool pin"}},
		{name: "check, pin register absent (--tags host-annotations): fails", play: kdcPlay{check: true, krb5Conf: badConf, pool: []string{bad}, admin: bad, pin: nil, resolvConf: resolv},
			wantReas: "no_pending_pin", mustHave: []string{"localhost cannot resolve " + bad, "--tags skipped the pin task"}},
		{name: "check, pin pending, NOT covered (name outside the pool): fails", play: kdcPlay{check: true, krb5Conf: badConf, pool: []string{"ipa7.pilot168.invalid"}, admin: "ipa7.pilot168.invalid", pin: pending, resolvConf: resolv},
			wantReas: "not_covered_by_pin",
			mustHave: []string{"localhost cannot resolve", bad, "only pins the active pool members (ipa7.pilot168.invalid)", "none of them is a pool member"}},
		{name: "check, resolvable: ok", play: kdcPlay{check: true, krb5Conf: goodConf, pool: []string{"localhost"}, admin: "localhost", pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "ok"},
		{name: "real run, resolvable: ok", play: kdcPlay{check: false, krb5Conf: goodConf, pool: []string{"localhost"}, admin: "localhost", pin: nil, resolvConf: resolv},
			wantOK: true, wantState: "ok"},
		{name: "real run, stale extra KDC name only: ok with a note", play: kdcPlay{check: false, krb5Conf: staleConf, pool: []string{"localhost"}, admin: "localhost", pin: nil, resolvConf: resolv},
			wantOK: true, wantState: "ok", mustHave: []string{"ipa9.pilot168.invalid", "do not need them"}},

		// Finding A (PR #180 review): kinit works when ANY one KDC name resolves,
		// so a pin that makes the active KDC resolvable defers the preview even
		// though a retired KDC name in krb5.conf stays unresolvable (apply's
		// server-list reconciliation drops it, but it is skipped under --check
		// and not predicted by this preview).
		{name: "A: check, active+retired KDC, pin covers the active one: deferred", play: kdcPlay{check: true, krb5Conf: activeRetiredConf, pool: []string{active}, admin: active, pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "deferred", wantReas: "pin_pending",
			mustHave: []string{active, retired, "makes " + active + " resolvable", "other stale KDC names in krb5.conf are left to the server-list reconciliation that apply performs"},
			mustNot:  []string{"cannot repair", "not_covered"}},
		{name: "A: check, a pinned KDC and a different pinned admin endpoint: deferred naming both", play: kdcPlay{check: true, krb5Conf: activeRetiredConf, pool: []string{active, "adm.pilot168.invalid"}, admin: "adm.pilot168.invalid", pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "deferred", wantReas: "pin_pending",
			mustHave: []string{"makes " + active + " and the admin endpoint adm.pilot168.invalid resolvable"}},
		{name: "A: check, active+retired KDC, no KDC in the pool: fails not covered", play: kdcPlay{check: true, krb5Conf: activeRetiredConf, pool: []string{"other.pilot168.invalid"}, admin: "other.pilot168.invalid", pin: pending, resolvConf: resolv},
			wantReas: "not_covered_by_pin",
			mustHave: []string{"only pins the active pool members (other.pilot168.invalid)", "none of them is a pool member", active, retired},
			mustNot:  []string{"cannot repair"}},
		{name: "A: check, active+retired KDC, no pending pin: fails", play: kdcPlay{check: true, krb5Conf: activeRetiredConf, pool: []string{active}, admin: active, pin: notPending, resolvConf: resolv},
			wantReas: "no_pending_pin", mustHave: []string{"no pending /etc/hosts server-pool pin"}},
		{name: "A: real run, active+retired KDC, pin pending: fails (apply wrote the pin first, so the resolver is the cause)", play: kdcPlay{check: false, krb5Conf: activeRetiredConf, pool: []string{active}, admin: active, pin: pending, resolvConf: resolv},
			wantReas: "unresolved_after_pin", mustHave: []string{"the resolver and /etc/nsswitch.conf hosts: are the cause"}},
		{name: "A: check, a KDC is in the pool but the admin endpoint is not: fails not covered", play: kdcPlay{check: true, krb5Conf: activeRetiredConf, pool: []string{active}, admin: "outside.pilot168.invalid", pin: pending, resolvConf: resolv},
			wantReas: "not_covered_by_pin",
			mustHave: []string{"the admin endpoint outside.pilot168.invalid is not a pool member"},
			mustNot:  []string{"none of them is a pool member"}},
		{name: "A: check, retired-only KDC (every configured KDC outside the pool): fails, preview does not predict failover", play: kdcPlay{check: true, krb5Conf: retiredOnlyConf, pool: []string{active}, admin: active, pin: pending, resolvConf: resolv},
			wantReas: "not_covered_by_pin",
			mustHave: []string{"none of them is a pool member", "does not predict the krb5.conf server-list reconciliation that apply performs", retired},
			mustNot:  []string{"cannot repair"}},

		// Finding B (PR #180 review): a quoted value is a valid libkrb5 profile
		// string; the probe must decode the quotes before it splits host:port.
		{name: "B: check, kdc = \"localhost:88\" on a healthy host: ok", play: kdcPlay{check: true, krb5Conf: quotedLocalConf, pool: []string{"localhost"}, admin: "localhost", pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "ok", mustNot: []string{"cannot resolve"}},
		{name: "B: real run, kdc = \"localhost:88\" on a healthy host: ok", play: kdcPlay{check: false, krb5Conf: quotedLocalConf, pool: []string{"localhost"}, admin: "localhost", pin: nil, resolvConf: resolv},
			wantOK: true, wantState: "ok", mustNot: []string{"cannot resolve"}},
		{name: "B control: the same KDC written without quotes: ok", play: kdcPlay{check: true, krb5Conf: plainLocalConf, pool: []string{"localhost"}, admin: "localhost", pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "ok"},
		{name: "B combined: quoted KDC in the pool, pin pending: deferred", play: kdcPlay{check: true, krb5Conf: quotedActiveConf, pool: []string{active}, admin: active, pin: pending, resolvConf: resolv},
			wantOK: true, wantState: "deferred", wantReas: "pin_pending", mustHave: []string{"localhost cannot resolve " + active}, mustNot: []string{`"` + active}},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			out, ok := c.play.run(t)
			if ok != c.wantOK {
				t.Fatalf("ansible-playbook success = %v, want %v\n%s", ok, c.wantOK, out)
			}
			if c.wantOK {
				if !strings.Contains(out, "PREFLIGHT_STATE="+c.wantState+" REASON="+c.wantReas+`"`) {
					t.Errorf("want state %q reason %q\n%s", c.wantState, c.wantReas, out)
				}
			}
			// A failure names its reason through the hint text; exactly the hint of
			// the expected reason must be there.
			hints := map[string]string{
				"not_covered_by_pin":   "only pins the active pool members",
				"no_pending_pin":       "no pending /etc/hosts server-pool pin",
				"unresolved_after_pin": "the resolver and /etc/nsswitch.conf hosts: are the cause",
			}
			if !c.wantOK {
				for reason, hint := range hints {
					if has := strings.Contains(out, hint); has != (reason == c.wantReas) {
						t.Errorf("reason %s: hint %q present = %v, expected reason is %q\n%s", reason, hint, has, c.wantReas, out)
					}
				}
			}
			for _, s := range c.mustHave {
				if !strings.Contains(out, s) {
					t.Errorf("output lacks %q\n%s", s, out)
				}
			}
			for _, s := range c.mustNot {
				if strings.Contains(out, s) {
					t.Errorf("output must not contain %q\n%s", s, out)
				}
			}
			if strings.Contains(out, "hidden due to the fact that") || strings.Contains(out, `"censored"`) {
				t.Errorf("the preflight must never be censored\n%s", out)
			}
			if !c.wantOK && c.wantReas != "" && !strings.Contains(out, "FAILED!") {
				t.Errorf("expected a task failure\n%s", out)
			}
		})
	}
}

// kinitFixture is one testdata/kinit-failures/*.txt file.
type kinitFixture struct {
	name, source, class, rc, stdout, stderr string
}

func loadKinitFixtures(t *testing.T) []kinitFixture {
	t.Helper()
	files, err := filepath.Glob("testdata/kinit-failures/*.txt")
	if err != nil || len(files) == 0 {
		t.Fatalf("no kinit fixtures: %v", err)
	}
	var out []kinitFixture
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fx := kinitFixture{name: strings.TrimSuffix(filepath.Base(f), ".txt")}
		section := ""
		var so, se []string
		for _, line := range strings.Split(string(raw), "\n") {
			switch {
			case strings.HasPrefix(line, "# source: "):
				fx.source = strings.TrimPrefix(line, "# source: ")
			case strings.HasPrefix(line, "# class: "):
				fx.class = strings.TrimPrefix(line, "# class: ")
			case strings.HasPrefix(line, "# rc="):
				fx.rc = strings.TrimPrefix(line, "# rc=")
			case line == "# --- stdout ---":
				section = "stdout"
			case line == "# --- stderr ---":
				section = "stderr"
			case section == "stdout":
				so = append(so, line)
			case section == "stderr":
				se = append(se, line)
			}
		}
		fx.stdout = strings.TrimSpace(strings.Join(so, "\n"))
		fx.stderr = strings.TrimSpace(strings.Join(se, "\n"))
		out = append(out, fx)
	}
	return out
}

// TestRegression_KinitFixturesAreHonestlyLabelled keeps the §5.6 rule: a
// fixture is either a live capture or says in its header that it is libkrb5
// error-table text (or synthetic), never silently passed off as a capture.
func TestRegression_KinitFixturesAreHonestlyLabelled(t *testing.T) {
	live, table := 0, 0
	for _, fx := range loadKinitFixtures(t) {
		switch {
		case strings.HasPrefix(fx.source, "live capture, MIT krb5 1.22.2"):
			live++
		case strings.Contains(fx.source, "NOT a live capture") || strings.HasPrefix(fx.source, "synthetic"):
			table++
		default:
			t.Errorf("%s: source %q must be a live capture or say it is not one", fx.name, fx.source)
		}
		if fx.class == "" || fx.stderr == "" {
			t.Errorf("%s: missing class or stderr", fx.name)
		}
	}
	if live < 5 || table < 3 {
		t.Errorf("fixture mix changed: live=%d not-live=%d", live, table)
	}
}

// TestRegression_KinitResultClassification runs the real shared
// classification file for every fixture, with and without the preflight
// evidence, and checks that the class is right, that a success passes, and
// that the raw stderr never reaches the output.
func TestRegression_KinitResultClassification(t *testing.T) {
	requireAnsibleForKDCTests(t)
	resultAbs, _ := filepath.Abs(kinitResultPath)

	type tcase struct {
		Name      string   `json:"name"`
		RC        string   `json:"rc"`
		Stderr    string   `json:"stderr"`
		Required  []string `json:"required"`
		Optional  []string `json:"optional"`
		WantClass string   `json:"-"`
	}
	var cases []tcase
	for _, fx := range loadKinitFixtures(t) {
		cases = append(cases, tcase{Name: fx.name, RC: fx.rc, Stderr: fx.stderr, WantClass: fx.class, Required: []string{}, Optional: []string{}})
	}
	// The same stderr means two different things; only the preflight tells
	// them apart.
	byName := map[string]kinitFixture{}
	for _, fx := range loadKinitFixtures(t) {
		byName[fx.name] = fx
	}
	cases = append(cases,
		tcase{Name: "kdc-name-unresolvable+preflight-unresolved", RC: "1", Stderr: byName["kdc-name-unresolvable"].stderr, Required: []string{"ipa1.pilot168.invalid"}, Optional: []string{}, WantClass: "cannot_resolve"},
		// A stale name that kinit does not need (another KDC resolves) is only
		// "unresolved", not "required": a closed KDC port stays cannot_contact_kdc.
		tcase{Name: "kdc-port-closed+optional-unresolved-name", RC: "1", Stderr: byName["kdc-port-closed"].stderr, Required: []string{}, Optional: []string{"retired.pilot168.invalid"}, WantClass: "cannot_contact_kdc"},
		tcase{Name: "kdc-port-closed+preflight-ok", RC: "1", Stderr: byName["kdc-port-closed"].stderr, Required: []string{}, Optional: []string{}, WantClass: "cannot_contact_kdc"},
		// Wrong password and a dead KDC must not be confused in either direction.
		tcase{Name: "wrong-password+preflight-unresolved", RC: "1", Stderr: byName["wrong-password"].stderr, Required: []string{"ipa1.pilot168.invalid"}, Optional: []string{}, WantClass: "preauth_failed"},
		tcase{Name: "success", RC: "0", Stderr: "", Required: []string{}, Optional: []string{}, WantClass: "ok"},
		tcase{Name: "binary-missing", RC: "2", Stderr: "[Errno 2] No such file or directory: b'kinit'", Required: []string{}, Optional: []string{}, WantClass: "other"},
	)

	dir := t.TempDir()
	caseFile := filepath.Join(dir, "case.yml")
	wrapper := `- block:
    - ansible.builtin.include_tasks:
        file: ` + resultAbs + `
      vars:
        freeipa_client_kinit_rc: "{{ case.rc }}"
        freeipa_client_kinit_stderr: "{{ case.stderr }}"
        freeipa_client_kdc_preflight_required_unresolved: "{{ case.required }}"
        freeipa_client_kdc_preflight_unresolved: "{{ (case.required + case.optional) | unique | list }}"
    - ansible.builtin.debug:
        msg: "RESULT {{ case.name }} class={{ freeipa_client_kinit_class }} PASSED"
  rescue:
    - ansible.builtin.debug:
        msg: "RESULT {{ case.name }} class={{ freeipa_client_kinit_class | default('unset') }} FAILED: {{ ansible_failed_result.msg }}"
`
	if err := os.WriteFile(caseFile, []byte(wrapper), 0o600); err != nil {
		t.Fatal(err)
	}
	playBody, _ := yaml.Marshal([]map[string]any{{
		"name": "classify", "hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": map[string]any{"ipa_enroll_principal": "admin", "ipa_realm": "IPA.PILOT.INTERNAL"},
		"tasks": []any{map[string]any{
			"ansible.builtin.include_tasks": caseFile,
			"loop":                          "{{ cases }}",
			"loop_control":                  map[string]any{"loop_var": "case", "label": "{{ case.name }}"},
		}},
	}})
	play := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(play, playBody, 0o600); err != nil {
		t.Fatal(err)
	}
	varsJSON, _ := json.Marshal(map[string]any{"cases": cases})
	varsFile := filepath.Join(dir, "vars.json")
	if err := os.WriteFile(varsFile, varsJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", play, "-e", "@"+varsFile)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	for _, c := range cases {
		re := regexp.MustCompile(`RESULT ` + regexp.QuoteMeta(c.Name) + ` class=(\S+) (PASSED|FAILED: [^"]*)`)
		m := re.FindStringSubmatch(out)
		if m == nil {
			t.Errorf("%s: no result line\n%s", c.Name, out)
			continue
		}
		if m[1] != c.WantClass {
			t.Errorf("%s: class = %s, want %s", c.Name, m[1], c.WantClass)
		}
		if (c.WantClass == "ok") != (m[2] == "PASSED") {
			t.Errorf("%s: gate outcome %q for class %s", c.Name, m[2], c.WantClass)
		}
		if c.WantClass != "ok" {
			for _, want := range []string{"admin@IPA.PILOT.INTERNAL", "kinit rc=" + c.RC, "class=" + c.WantClass} {
				if !strings.Contains(m[2], want) {
					t.Errorf("%s: failure text %q lacks %q", c.Name, m[2], want)
				}
			}
		}
		// Raw stderr is withheld: no fixture line may reach the output.
		if c.Stderr != "" && strings.Contains(out, c.Stderr) {
			t.Errorf("%s: raw kinit stderr %q leaked into the output", c.Name, c.Stderr)
		}
	}
}

// TestRegression_KinitFailureNeverLeaksSecret runs the real kinit task of
// both callers followed by the shared classification, with a fake kinit that
// fails and echoes the password it read on stdin into its stderr (a hostile
// worst case). Neither the password nor the echoed stderr may reach the
// output, and the failure must still say what class it is.
func TestRegression_KinitFailureNeverLeaksSecret(t *testing.T) {
	requireAnsibleForKDCTests(t)
	resultAbs, _ := filepath.Abs(kinitResultPath)
	for _, tc := range []struct {
		file, task, ccacheVar, includeName string
	}{
		{"freeipa-host-annotations.yml", "FreeIPA host annotations — kinit admin into the dedicated ccache", "ipa_annotations_ccache_file", "FreeIPA host annotations — kinit result: classify and gate (raw output withheld)"},
		{"freeipa-host-access-policy.yml", "FreeIPA host access policy — kinit admin into the dedicated ccache", "ipa_host_policy_ccache_file", "FreeIPA host access policy — kinit result: classify and gate (raw output withheld)"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			doc := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", "tasks", tc.file))
			kinit := findNamedTask(t, doc, tc.task)
			include := findNamedTask(t, doc, tc.includeName)
			// The shared file is referenced by a sibling-relative name; make it absolute.
			inc := include["ansible.builtin.include_tasks"].(map[string]any)
			inc["file"] = resultAbs

			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			fake := "#!/bin/sh\npw=$(cat)\nprintf 'kinit: Password incorrect while getting initial credentials (typed: %s)\\n' \"$pw\" >&2\nexit 1\n"
			if err := os.WriteFile(filepath.Join(bin, "kinit"), []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}
			const secret = "S3cretPassw0rd-168"
			play := []map[string]any{{
				"name": "kinit", "hosts": "localhost", "connection": "local", "gather_facts": false,
				"vars": map[string]any{
					"ipa_enroll_password": unsafeString(secret), "ipa_enroll_principal": "admin", "ipa_realm": "IPA.PILOT.INTERNAL",
					tc.ccacheVar: map[string]any{"path": filepath.Join(dir, "cc")},
				},
				"environment": map[string]any{"PATH": bin + ":" + os.Getenv("PATH")},
				"tasks":       []any{kinit, include},
			}}
			body, _ := yaml.Marshal(play)
			path := filepath.Join(dir, "play.yml")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			// -vvv shows task results; no_log must still hide the kinit result.
			cmd := exec.Command("ansible-playbook", "-vvv", "-i", "localhost,", path)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
			raw, err := cmd.CombinedOutput()
			out := string(raw)
			if err == nil {
				t.Fatalf("a failing kinit must fail the play\n%s", out)
			}
			if strings.Contains(out, secret) {
				t.Errorf("the password reached the output\n%s", out)
			}
			if strings.Contains(out, "typed:") {
				t.Errorf("raw kinit stderr reached the output\n%s", out)
			}
			for _, want := range []string{"class=preauth_failed", "kinit rc=1", "admin@IPA.PILOT.INTERNAL", "pre-authentication failed"} {
				if !strings.Contains(out, want) {
					t.Errorf("failure text lacks %q\n%s", want, out)
				}
			}
		})
	}
}

// taskIncluding returns the task (map) whose include_tasks file is `file`.
func taskIncluding(doc any, file string) map[string]any {
	var found map[string]any
	walkTaskMaps(doc, func(m map[string]any) {
		if inc, ok := m["ansible.builtin.include_tasks"].(map[string]any); ok && inc["file"] == file {
			found = m
		}
	})
	return found
}

func taskText(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRegression_KDCPreflightWiring locks the static invariants of the two
// shared files and of how the two callers use them.
func TestRegression_KDCPreflightWiring(t *testing.T) {
	t.Run("preflight file", func(t *testing.T) {
		raw, err := os.ReadFile(kdcPreflightPath)
		if err != nil {
			t.Fatal(err)
		}
		doc := loadYAML(t, kdcPreflightPath)
		tasks, _ := doc.([]any)
		if len(tasks) == 0 {
			t.Fatal("no tasks")
		}
		// 1. It is included twice per play, so the first task resets every fact it owns.
		first, _ := tasks[0].(map[string]any)
		facts, _ := first["ansible.builtin.set_fact"].(map[string]any)
		if facts == nil {
			t.Fatalf("the first task must be a set_fact that resets this file's state, got %v", first["name"])
		}
		for _, f := range []string{"state", "unresolved", "required_unresolved", "resolvers", "reason", "summary", "kdc_unusable", "admin_unresolved", "kdc_names", "unparsable"} {
			if _, ok := facts["freeipa_client_kdc_preflight_"+f]; !ok {
				t.Errorf("the reset task does not reset freeipa_client_kdc_preflight_%s", f)
			}
		}
		// 2. The probe is bounded, read-only and runs under --check.
		probe := taskText(t, findNamedTask(t, doc, kdcPreflightProbe))
		for _, want := range []string{"- timeout", "check_mode: false", "changed_when: false", "failed_when: false", "ansible.builtin.command"} {
			if !strings.Contains(probe, want) {
				t.Errorf("probe task lacks %q", want)
			}
		}
		// 3. Nothing here handles a secret, so nothing may be censored.
		walkTaskMaps(doc, func(m map[string]any) {
			if m["no_log"] == true {
				t.Errorf("task %v is no_log: the preflight failure must never be censored", m["name"])
			}
			if _, ok := m["ansible.builtin.shell"]; ok {
				t.Errorf("task %v uses shell", m["name"])
			}
		})
		// 4. The gate reads the state and the deferral only happens in check mode.
		text := string(raw)
		for _, want := range []string{"ansible_check_mode and freeipa_client_kdc_preflight_pin_pending", "freeipa_client_hosts_pool_pin | default({})", "state != 'failed'"} {
			if !strings.Contains(text, want) {
				t.Errorf("preflight file lacks %q", want)
			}
		}
	})

	t.Run("kinit-result file", func(t *testing.T) {
		doc := loadYAML(t, kinitResultPath)
		classify := findNamedTask(t, doc, "FreeIPA kinit result — classify the exit code and stderr (stderr is never printed)")
		if classify["no_log"] != true {
			t.Error("the classification set_fact must be no_log (it templates the raw stderr)")
		}
		gate := findNamedTask(t, doc, "FreeIPA kinit result — gate: admin kinit must succeed (fixed text only, raw stderr withheld)")
		if gate["no_log"] == true {
			t.Error("the gate must not be no_log: the class has to be visible")
		}
		args, _ := gate["ansible.builtin.assert"].(map[string]any)
		failMsg, _ := args["fail_msg"].(string)
		if failMsg == "" {
			t.Fatal("gate has no fail_msg")
		}
		if strings.Contains(failMsg, "stderr") || strings.Contains(failMsg, "stdout") {
			t.Errorf("the gate message must never reference the raw output: %q", failMsg)
		}
		vars, _ := classify["vars"].(map[string]any)
		for _, re := range []string{"resolve", "contact", "preauth", "client_not_found", "clock_skew"} {
			if _, ok := vars["freeipa_client_kinit_re_"+re]; !ok {
				t.Errorf("classification regex %s missing from the task vars", re)
			}
		}
	})

	for _, tc := range []struct {
		file, caller, stat, kinitName string
	}{
		{"freeipa-host-annotations.yml", "FreeIPA host annotations", "ipa_annotations_enrolled_stat", "FreeIPA host annotations — kinit admin into the dedicated ccache"},
		{"freeipa-host-access-policy.yml", "FreeIPA host access policy", "ipa_host_policy_enrolled_stat", "FreeIPA host access policy — kinit admin into the dedicated ccache"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("..", "..", "playbooks", "apply", "tasks", tc.file)
			rawBytes, _ := os.ReadFile(path)
			raw := string(rawBytes)
			doc := loadYAML(t, path)

			pre := taskIncluding(doc, "freeipa-client-kdc-preflight.yml")
			if pre == nil {
				t.Fatal("the preflight is not included")
			}
			inc := pre["ansible.builtin.include_tasks"].(map[string]any)
			apply, _ := inc["apply"].(map[string]any)
			if tags, _ := apply["tags"].([]any); len(tags) != 1 || tags[0] != "always" {
				t.Errorf("the shared preflight include must use apply: {tags: [always]} (§4.5 item 8), got %v", apply)
			}
			if w, _ := pre["when"].(string); !strings.Contains(w, tc.stat) {
				t.Errorf("the preflight must run only on an enrolled host, when = %v", pre["when"])
			}
			if v, _ := pre["vars"].(map[string]any); v["freeipa_client_kdc_preflight_caller"] != tc.caller {
				t.Errorf("caller label = %v, want %q", v["freeipa_client_kdc_preflight_caller"], tc.caller)
			}

			// The enrolled block is gated on a state fixed before it, and nothing inside
			// the block (or the shared files it includes) changes that state.
			iPre := strings.Index(raw, "file: freeipa-client-kdc-preflight.yml")
			iDefault := strings.Index(raw, "freeipa_client_kdc_preflight_state: skipped")
			iGate := strings.Index(raw, "freeipa_client_kdc_preflight_state != 'deferred'")
			iKinit := strings.Index(raw, tc.kinitName)
			if iDefault < 0 || iDefault >= iPre || iPre >= iGate || iGate >= iKinit {
				t.Errorf("order must be: state default (%d) < preflight include (%d) < block gate (%d) < kinit (%d)", iDefault, iPre, iGate, iKinit)
			}
			if strings.Count(raw, "freeipa_client_kdc_preflight_state:") != 1 {
				t.Errorf("only the default set_fact may write the state in the caller (the block's when: is re-evaluated per task)")
			}
			kinitRaw, _ := os.ReadFile(kinitResultPath)
			if strings.Contains(string(kinitRaw), "freeipa_client_kdc_preflight_state:") {
				t.Error("the kinit-result file must not write the preflight state")
			}

			// The kinit task: stdin password, no shell, no_log, classified afterwards.
			kinit := findNamedTask(t, doc, tc.kinitName)
			if kinit["no_log"] != true || kinit["check_mode"] != false || kinit["failed_when"] != false {
				t.Errorf("kinit must be no_log, check_mode: false and failed_when: false (the gate fails with a classified message): %v", kinit)
			}
			if _, ok := kinit["register"]; !ok {
				t.Error("kinit must register its result for the classification")
			}
			if _, ok := kinit["ansible.builtin.command"].(map[string]any)["stdin"]; !ok {
				t.Error("the password must go in on stdin")
			}
			if strings.Contains(raw, "ansible.builtin.shell") {
				t.Error("no shell task may remain in this file (the kinit pipe was the last one)")
			}
			res := taskIncluding(doc, "freeipa-client-kinit-result.yml")
			if res == nil {
				t.Fatal("the kinit classification is not included")
			}
			resVars, _ := res["vars"].(map[string]any)
			for k, v := range resVars {
				s, _ := v.(string)
				if !strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(s, "}}")), ".rc | default(1)") &&
					!strings.Contains(s, ".stderr | default('')") {
					t.Errorf("include var %s = %q: pass only the exit code and stderr, never the whole register (it holds the password)", k, s)
				}
			}
			if rIdx := strings.Index(raw, "file: freeipa-client-kinit-result.yml"); rIdx < iKinit {
				t.Error("the classification must follow the kinit task")
			}
		})
	}

	t.Run("pool pin registers its result", func(t *testing.T) {
		doc := loadYAML(t, "../../playbooks/apply/freeipa-client-apply.yml")
		pin := findNamedTask(t, doc, "FreeIPA client — pin the FreeIPA server pool to /etc/hosts (pool-aware managed block, spec §6)")
		if pin["register"] != "freeipa_client_hosts_pool_pin" {
			t.Errorf("the pin task must register freeipa_client_hosts_pool_pin (the preflight reads it), got %v", pin["register"])
		}
	})
}
