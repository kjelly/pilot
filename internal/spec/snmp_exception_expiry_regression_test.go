package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const snmpExceptionGateName = "Gate: prod stage rejects insecure SNMP auth profiles unless an explicit reviewed exception exists"

// snmpExceptionGate returns the prod insecure-profile gate from
// snmp-exporter-apply.yml's pre_tasks.
func snmpExceptionGate(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/snmp-exporter-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	for _, play := range plays {
		tasks, _ := play["pre_tasks"].([]any)
		for _, task := range tasks {
			if m, ok := task.(map[string]any); ok && m["name"] == snmpExceptionGateName {
				return m
			}
		}
	}
	t.Fatalf("%q not found in snmp-exporter-apply.yml pre_tasks", snmpExceptionGateName)
	return nil
}

// snmpExceptionCase is one run of the prod gate: the exception for lab-v2c
// as an operator writes it in a vars file (empty: none), the cached
// ansible_date_time.date the gate used to read, and whether it is accepted.
// exceptions is the body of lab-v2c's flow mapping, or, when it starts with
// snmpExceptionsVar, the vars file's whole exceptions setting.
type snmpExceptionCase struct {
	name       string
	exceptions string
	factDate   string
	accept     bool
}

// snmpValidException is a complete prod exception for lab-v2c apart from
// its expiry, which each expiry case appends.
const snmpValidException = `reason: lab, owner: ops, confirmed: true, networkEvidence: "CHG-1 mgmt VLAN ACL", `

// snmpExceptionsVar is the exceptions variable, which a case's exceptions
// may start with to give the whole setting instead of lab-v2c's fields.
const snmpExceptionsVar = "snmp_insecure_auth_profile_exceptions:"

// runSnmpExceptionCases runs the prod gate from snmp-exporter-apply.yml
// through Ansible on localhost once per case, with a v3 authPriv profile
// (never rejected) and the v2c profile lab-v2c.
func runSnmpExceptionCases(t *testing.T, cases []snmpExceptionCase) {
	t.Helper()
	gate := snmpExceptionGate(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			exceptions := snmpExceptionsVar + " {}\n"
			switch {
			case strings.HasPrefix(tc.exceptions, snmpExceptionsVar):
				exceptions = tc.exceptions + "\n"
			case tc.exceptions != "":
				exceptions = snmpExceptionsVar + "\n  lab-v2c: {" + tc.exceptions + "}\n"
			}
			varsFile := filepath.Join(dir, "exceptions.yml")
			body := exceptions + "ansible_date_time: {date: \"" + tc.factDate + "\"}\n"
			if err := os.WriteFile(varsFile, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{
				"stage": "prod",
				"snmp_catalog_parsed": map[string]any{"authProfiles": map[string]any{
					"core-v3": map[string]any{"version": 3, "securityLevel": "authPriv", "credentialRef": "core"},
					"lab-v2c": map[string]any{"version": 2, "securityLevel": "noAuthNoPriv", "credentialRef": "lab"},
				}},
			}
			res := runLocalTasks(t, vars, []map[string]any{gate}, dir, nil, "-e", "@"+varsFile)
			if !res.ran[snmpExceptionGateName] {
				t.Fatalf("the gate did not run:\n%s", res.raw)
			}
			if tc.accept {
				if res.rc != 0 || len(res.failures) > 0 {
					t.Fatalf("gate rejected a valid exception (rc=%d): %v", res.rc, res.failures)
				}
				return
			}
			if res.rc == 0 {
				t.Fatal("gate accepted the exception, want a rejection")
			}
			// The task message is "One or more items failed"; each item's
			// message is in the JSON callback's results.
			if len(res.failures) != 1 || !strings.HasPrefix(res.failures[0], snmpExceptionGateName+":") ||
				!strings.Contains(res.raw, `authProfile \"lab-v2c\" is version 2`) ||
				!strings.Contains(res.raw, "which prod rejects unless") ||
				strings.Contains(res.raw, `authProfile \"core-v3\"`) {
				t.Fatalf("want the gate to reject lab-v2c only, got rc=%d %v\n%s", res.rc, res.failures, res.raw)
			}
		})
	}
}

// snmpTestDays returns a formatter for today's UTC date plus an offset, and
// skips the test near UTC midnight, where the gate's today could differ
// from the test's.
func snmpTestDays(t *testing.T) func(int) string {
	t.Helper()
	now := time.Now().UTC()
	if next := now.Truncate(24 * time.Hour).Add(24 * time.Hour); next.Sub(now) < 2*time.Minute {
		t.Skip("too close to UTC midnight: the gate's today could differ from the test's")
	}
	return func(offset int) string { return now.AddDate(0, 0, offset).Format("2006-01-02") }
}

// TestRegression_SnmpInsecureProfileExceptionExpiry runs the prod gate
// (docs/verification/snmp-exporter.md C12 v1.1) with exceptions that are
// complete except for their expiry. They are written to a vars file the way
// an operator writes them, so `expiry: 2099-12-31` loads as a YAML date.
// Each case also sets ansible_date_time.date, the cached fact the gate used
// to read: today's date, except in the stale-cache case.
//
// Against the old gate (expiry >= ansible_date_time.date):
//   - the bare YAML date fails with a type error instead of passing;
//   - the unpadded past date 2026-9-30 passes;
//   - the stale fact accepts an exception that expired yesterday (UTC).
//
// Against the first version of the new gate, which checked only the
// YYYY-MM-DD shape, the six quoted impossible dates pass (PR #64 review).
func TestRegression_SnmpInsecureProfileExceptionExpiry(t *testing.T) {
	day := snmpTestDays(t)
	runSnmpExceptionCases(t, []snmpExceptionCase{
		{"no exception", ``, day(0), false},
		{"quoted future expiry", snmpValidException + `expiry: "2099-12-31"`, day(0), true},
		{"bare YAML date in the future", snmpValidException + `expiry: 2099-12-31`, day(0), true},
		{"expires today (UTC), still valid", snmpValidException + `expiry: "` + day(0) + `"`, day(0), true},
		{"expired yesterday (UTC)", snmpValidException + `expiry: "` + day(-1) + `"`, day(0), false},
		{"expired yesterday, with a stale cached fact", snmpValidException + `expiry: "` + day(-1) + `"`, day(-1), false},
		{"unpadded past date", snmpValidException + `expiry: "2026-9-30"`, "2026-10-13", false},
		{"missing expiry", `reason: lab, owner: ops, confirmed: true, networkEvidence: "CHG-1"`, day(0), false},
		// Quoted, so they reach the gate as strings; unquoted, Ansible
		// already refuses to load them ("month must be in 1..12").
		{"month 13", snmpValidException + `expiry: "2099-13-01"`, day(0), false},
		{"February 29 in a common year", snmpValidException + `expiry: "2099-02-29"`, day(0), false},
		{"February 29 in a century common year", snmpValidException + `expiry: "2100-02-29"`, day(0), false},
		{"April 31", snmpValidException + `expiry: "2099-04-31"`, day(0), false},
		{"month and day zero", snmpValidException + `expiry: "2099-00-00"`, day(0), false},
		{"9999-99-99", snmpValidException + `expiry: "9999-99-99"`, day(0), false},
		{"February 29 in a leap year", snmpValidException + `expiry: "2096-02-29"`, day(0), true},
		{"February 29 in a 400-year leap year", snmpValidException + `expiry: "2400-02-29"`, day(0), true},
		{"bare leap day", snmpValidException + `expiry: 2096-02-29`, day(0), true},
	})
}

// TestRegression_SnmpInsecureProfileExceptionFields runs the prod gate
// (C12 v1.3) with a valid expiry and one of the other fields wrong. Spec
// §13.2 requires all five: confirm insecure SNMP (`confirmed`, the boolean
// true), reason, expiry, owner and restricted management network evidence
// (`networkEvidence`). Against the v1.1 gate, which checked only reason,
// owner and expiry, every confirmed/networkEvidence rejection here passes.
//
// reason and owner must be non-blank strings, networkEvidence a non-blank
// string or a number (a ticket number). Against the v1.2 gate, which turned
// networkEvidence into a string before checking its length and took the
// length of reason and owner as they were, null, an empty list or an empty
// mapping passed as networkEvidence, a list or mapping passed as reason or
// owner, and a blank reason or owner passed (PR #65 review). A null or
// non-mapping exception, or a null exceptions setting, raised a templating
// error instead of the gate's message.
func TestRegression_SnmpInsecureProfileExceptionFields(t *testing.T) {
	day := snmpTestDays(t)
	const expiry = `expiry: "2099-12-31"`
	const valid = `confirmed: true, reason: lab, owner: ops, networkEvidence: "CHG-1", `
	// without returns the valid fields with one replaced: field "" drops it.
	without := func(field, value string) string {
		out := ""
		for _, kv := range strings.Split(strings.TrimSuffix(valid, ", "), ", ") {
			if strings.HasPrefix(kv, field+": ") {
				if value != "" {
					out += field + ": " + value + ", "
				}
				continue
			}
			out += kv + ", "
		}
		return out + expiry
	}
	runSnmpExceptionCases(t, []snmpExceptionCase{
		{"all five fields", snmpValidException + expiry, day(0), true},
		{"a ticket number as networkEvidence", without("networkEvidence", "1234"), day(0), true},
		{"confirmed missing", without("confirmed", ""), day(0), false},
		{"confirmed false", without("confirmed", "false"), day(0), false},
		{"confirmed is the string true", without("confirmed", `"true"`), day(0), false},
		{"networkEvidence missing", without("networkEvidence", ""), day(0), false},
		{"networkEvidence blank", without("networkEvidence", `"   "`), day(0), false},
		{"networkEvidence null", without("networkEvidence", "null"), day(0), false},
		{"networkEvidence empty list", without("networkEvidence", "[]"), day(0), false},
		{"networkEvidence empty mapping", without("networkEvidence", "{}"), day(0), false},
		{"networkEvidence list", without("networkEvidence", "[CHG-1]"), day(0), false},
		{"networkEvidence mapping", without("networkEvidence", "{ticket: CHG-1}"), day(0), false},
		{"networkEvidence boolean", without("networkEvidence", "true"), day(0), false},
		{"networkEvidence written as a bare key", snmpExceptionsVar + `
  lab-v2c:
    confirmed: true
    reason: lab
    owner: ops
    networkEvidence:
    ` + expiry, day(0), false},
		{"reason missing", without("reason", ""), day(0), false},
		{"reason blank", without("reason", `"   "`), day(0), false},
		{"reason null", without("reason", "null"), day(0), false},
		{"reason list", without("reason", "[lab]"), day(0), false},
		{"reason mapping", without("reason", "{why: lab}"), day(0), false},
		{"reason number", without("reason", "42"), day(0), false},
		{"owner missing", without("owner", ""), day(0), false},
		{"owner blank", without("owner", `"   "`), day(0), false},
		{"owner null", without("owner", "null"), day(0), false},
		{"owner list", without("owner", "[ops]"), day(0), false},
		{"owner mapping", without("owner", "{team: ops}"), day(0), false},
		{"the exception is null", snmpExceptionsVar + "\n  lab-v2c:", day(0), false},
		{"the exception is a list", snmpExceptionsVar + "\n  lab-v2c: [" + strings.TrimSuffix(valid, ", ") + "]", day(0), false},
		{"the exceptions setting is null", snmpExceptionsVar, day(0), false},
	})
}

// TestRegression_NoDecisionsOnCachedDateFacts is a repo-wide lint over
// playbooks/**: no that/when/failed_when/changed_when/until may read
// ansible_date_time. ansible.cfg caches facts for an hour (gathering =
// smart), and the fact is the target's local time, so a date check against
// it is up to an hour late and depends on the target's time zone. Compare
// with now(utc=true, ...) instead. The snmp-exporter exception gate did
// this until 2026-10-13.
func TestRegression_NoDecisionsOnCachedDateFacts(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	conditions := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		violations, checked := dateFactDecisions(doc)
		conditions += checked
		for _, v := range violations {
			t.Errorf("%s: %s", path, v)
		}
	}
	// Hundreds of tasks carry a when: or an assert; far fewer means the
	// walker stopped finding them.
	if conditions < 500 {
		t.Fatalf("only %d conditions found; the walker is broken", conditions)
	}
}

func TestDateFactDecisions(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"the old snmp-exporter gate", `
- name: g
  ansible.builtin.assert:
    that:
      - (x.get('expiry', '0000-00-00') >= ansible_date_time.date)
`, 1},
		{"when, nested in a block", `
- block:
    - name: t
      ansible.builtin.debug: {msg: hi}
      when: ansible_date_time.weekday == 'Monday'
`, 1},
		{"failed_when, changed_when and until", `
- name: t
  ansible.builtin.command: date
  failed_when: ansible_date_time.epoch | int > 0
  changed_when: "'x' in ansible_date_time.iso8601"
  until: ansible_date_time.hour == '00'
`, 3},
		{"a name or a message is not a decision", `
- name: "archive {{ ansible_date_time.iso8601_basic_short }}"
  ansible.builtin.debug:
    msg: "initialized at {{ ansible_date_time.iso8601 }}"
  when: stage == 'prod'
`, 0},
		{"the new gate", `
- name: g
  ansible.builtin.assert:
    that:
      - (x.get('expiry', '') | string) >= now(utc=true, fmt='%Y-%m-%d')
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := dateFactDecisions(doc)
			if len(got) != tc.want {
				t.Fatalf("got %d violations %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// dateFactDecisions returns one message per condition in doc that reads
// ansible_date_time, and the number of conditions it checked: the values of
// when/failed_when/changed_when/until, and the that: of assert tasks.
func dateFactDecisions(doc any) ([]string, int) {
	var out []string
	checked := 0
	var strs func(v any) []string
	strs = func(v any) []string {
		switch x := v.(type) {
		case string:
			return []string{x}
		case bool, int, float64:
			return []string{fmt.Sprint(x)}
		case []any:
			var s []string
			for _, item := range x {
				s = append(s, strs(item)...)
			}
			return s
		}
		return nil
	}
	check := func(task map[string]any, key string, v any) {
		for _, cond := range strs(v) {
			checked++
			if strings.Contains(cond, "ansible_date_time") {
				name, _ := task["name"].(string)
				out = append(out, fmt.Sprintf("task %q: %s: %q reads the cached, target-local ansible_date_time; compare with now(utc=true, ...)", name, key, strings.TrimSpace(cond)))
			}
		}
	}
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, c := range v {
				walk(c)
			}
		case map[string]any:
			for _, key := range []string{"when", "failed_when", "changed_when", "until"} {
				if c, ok := v[key]; ok {
					check(v, key, c)
				}
			}
			for _, module := range []string{"ansible.builtin.assert", "assert"} {
				if args, ok := v[module].(map[string]any); ok {
					check(v, "that", args["that"])
				}
			}
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return out, checked
}
