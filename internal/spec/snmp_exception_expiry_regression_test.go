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

// TestRegression_SnmpInsecureProfileExceptionExpiry runs the prod gate from
// snmp-exporter-apply.yml through Ansible on localhost (docs/verification/
// snmp-exporter.md C12 v1.1). The exceptions are written to a vars file the
// way an operator writes them, so `expiry: 2099-12-31` loads as a YAML date.
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
	now := time.Now().UTC()
	if next := now.Truncate(24 * time.Hour).Add(24 * time.Hour); next.Sub(now) < 2*time.Minute {
		t.Skip("too close to UTC midnight: the gate's today could differ from the test's")
	}
	day := func(offset int) string { return now.AddDate(0, 0, offset).Format("2006-01-02") }
	gate := snmpExceptionGate(t)
	cases := []struct {
		name       string
		exceptions string // YAML mapping for lab-v2c, as an operator writes it
		factDate   string // ansible_date_time.date
		accept     bool
	}{
		{"no exception", ``, day(0), false},
		{"quoted future expiry", `{reason: lab, owner: ops, expiry: "2099-12-31"}`, day(0), true},
		{"bare YAML date in the future", `{reason: lab, owner: ops, expiry: 2099-12-31}`, day(0), true},
		{"expires today (UTC), still valid", `{reason: lab, owner: ops, expiry: "` + day(0) + `"}`, day(0), true},
		{"expired yesterday (UTC)", `{reason: lab, owner: ops, expiry: "` + day(-1) + `"}`, day(0), false},
		{"expired yesterday, with a stale cached fact", `{reason: lab, owner: ops, expiry: "` + day(-1) + `"}`, day(-1), false},
		{"unpadded past date", `{reason: lab, owner: ops, expiry: "2026-9-30"}`, "2026-10-13", false},
		{"missing expiry", `{reason: lab, owner: ops}`, day(0), false},
		{"missing owner", `{reason: lab, expiry: "2099-12-31"}`, day(0), false},
		// Quoted, so they reach the gate as strings; unquoted, Ansible
		// already refuses to load them ("month must be in 1..12").
		{"month 13", `{reason: lab, owner: ops, expiry: "2099-13-01"}`, day(0), false},
		{"February 29 in a common year", `{reason: lab, owner: ops, expiry: "2099-02-29"}`, day(0), false},
		{"February 29 in a century common year", `{reason: lab, owner: ops, expiry: "2100-02-29"}`, day(0), false},
		{"April 31", `{reason: lab, owner: ops, expiry: "2099-04-31"}`, day(0), false},
		{"month and day zero", `{reason: lab, owner: ops, expiry: "2099-00-00"}`, day(0), false},
		{"9999-99-99", `{reason: lab, owner: ops, expiry: "9999-99-99"}`, day(0), false},
		{"February 29 in a leap year", `{reason: lab, owner: ops, expiry: "2096-02-29"}`, day(0), true},
		{"February 29 in a 400-year leap year", `{reason: lab, owner: ops, expiry: "2400-02-29"}`, day(0), true},
		{"bare leap day", `{reason: lab, owner: ops, expiry: 2096-02-29}`, day(0), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			exceptions := "snmp_insecure_auth_profile_exceptions: {}\n"
			if tc.exceptions != "" {
				exceptions = "snmp_insecure_auth_profile_exceptions:\n  lab-v2c: " + tc.exceptions + "\n"
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
