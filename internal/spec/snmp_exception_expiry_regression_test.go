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
// ansible_date_time.date the gate used to read, and the outcome. exceptions
// is the body of lab-v2c's flow mapping, or, when it starts with
// snmpExceptionsVar, the vars file's whole exceptions setting. reject is nil
// for an accepted exception; otherwise the gate must reject lab-v2c, and its
// message must contain each string in reject (what it says is wrong).
type snmpExceptionCase struct {
	name       string
	exceptions string
	factDate   string
	reject     []string
}

// snmpValidException is a complete prod exception for lab-v2c apart from
// its expiry, which each expiry case appends.
const snmpValidException = `reason: lab, owner: ops, confirmed: true, networkEvidence: "CHG-1 mgmt VLAN ACL", `

// snmpExceptionsVar is the exceptions variable, which a case's exceptions
// may start with to give the whole setting instead of lab-v2c's fields.
const snmpExceptionsVar = "snmp_insecure_auth_profile_exceptions:"

// snmpExceptionProfiles is the catalog the gate runs over: a v3 authPriv
// profile, never rejected, and the v2c profile lab-v2c.
func snmpExceptionProfiles() map[string]any {
	return map[string]any{"authProfiles": map[string]any{
		"core-v3": map[string]any{"version": 3, "securityLevel": "authPriv", "credentialRef": "core"},
		"lab-v2c": map[string]any{"version": 2, "securityLevel": "noAuthNoPriv", "credentialRef": "lab"},
	}}
}

// checkSnmpGateResult fails t unless res is the outcome reject asks for (see
// snmpExceptionCase): an accepted run, or the gate's own rejection of
// lab-v2c alone, naming each problem in reject.
func checkSnmpGateResult(t *testing.T, res fcRun, reject []string) {
	t.Helper()
	if !res.ran[snmpExceptionGateName] {
		t.Fatalf("the gate did not run:\n%s", res.raw)
	}
	if reject == nil {
		if res.rc != 0 || len(res.failures) > 0 {
			t.Fatalf("gate rejected a valid exception (rc=%d): %v\n%s", res.rc, res.failures, res.raw)
		}
		return
	}
	if res.rc == 0 {
		t.Fatal("gate accepted the exception, want a rejection")
	}
	// The task message is "One or more items failed"; each item's message
	// is in the JSON callback's results.
	if len(res.failures) != 1 || !strings.HasPrefix(res.failures[0], snmpExceptionGateName+":") ||
		!strings.Contains(res.raw, `authProfile \"lab-v2c\" is version 2`) ||
		!strings.Contains(res.raw, "which prod rejects unless") ||
		strings.Contains(res.raw, `authProfile \"core-v3\"`) {
		t.Fatalf("want the gate's own rejection of lab-v2c only, got rc=%d %v\n%s", res.rc, res.failures, res.raw)
	}
	for _, want := range reject {
		if !strings.Contains(res.raw, want) {
			t.Fatalf("the rejection does not say %q:\n%s", want, res.raw)
		}
	}
}

// runSnmpExceptionCases runs the prod gate from snmp-exporter-apply.yml
// through Ansible on localhost once per case, with the exceptions in a vars
// file passed with -e @file.
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
			vars := map[string]any{"stage": "prod", "snmp_catalog_parsed": snmpExceptionProfiles()}
			res := runLocalTasks(t, vars, []map[string]any{gate}, dir, nil, "-e", "@"+varsFile)
			checkSnmpGateResult(t, res, tc.reject)
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

// rejects is shorthand for the problems a rejection must name.
func rejects(problems ...string) []string { return problems }

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
	notADate := rejects("expiry is not a YYYY-MM-DD calendar date")
	runSnmpExceptionCases(t, []snmpExceptionCase{
		{"no exception", ``, day(0), rejects("there is no exception for this profile")},
		{"quoted future expiry", snmpValidException + `expiry: "2099-12-31"`, day(0), nil},
		{"bare YAML date in the future", snmpValidException + `expiry: 2099-12-31`, day(0), nil},
		{"expires today (UTC), still valid", snmpValidException + `expiry: "` + day(0) + `"`, day(0), nil},
		{"expired yesterday (UTC)", snmpValidException + `expiry: "` + day(-1) + `"`, day(0), rejects("expiry " + day(-1) + " has passed")},
		{"expired yesterday, with a stale cached fact", snmpValidException + `expiry: "` + day(-1) + `"`, day(-1), rejects("expiry " + day(-1) + " has passed")},
		{"unpadded past date", snmpValidException + `expiry: "2026-9-30"`, "2026-10-13", notADate},
		{"missing expiry", `reason: lab, owner: ops, confirmed: true, networkEvidence: "CHG-1"`, day(0), rejects("expiry is missing")},
		// Quoted, so they reach the gate as strings; unquoted, Ansible
		// already refuses to load them ("month must be in 1..12").
		{"month 13", snmpValidException + `expiry: "2099-13-01"`, day(0), notADate},
		{"February 29 in a common year", snmpValidException + `expiry: "2099-02-29"`, day(0), notADate},
		{"February 29 in a century common year", snmpValidException + `expiry: "2100-02-29"`, day(0), notADate},
		{"April 31", snmpValidException + `expiry: "2099-04-31"`, day(0), notADate},
		{"month and day zero", snmpValidException + `expiry: "2099-00-00"`, day(0), notADate},
		{"9999-99-99", snmpValidException + `expiry: "9999-99-99"`, day(0), notADate},
		{"February 29 in a leap year", snmpValidException + `expiry: "2096-02-29"`, day(0), nil},
		{"February 29 in a 400-year leap year", snmpValidException + `expiry: "2400-02-29"`, day(0), nil},
		{"bare leap day", snmpValidException + `expiry: 2096-02-29`, day(0), nil},
	})
}

// TestRegression_SnmpInsecureProfileExceptionFields runs the prod gate
// (C12 v1.4) with a valid expiry and the other fields varied. Spec §13.2
// requires all five: confirm insecure SNMP (`confirmed`, the boolean true),
// reason, expiry, owner and restricted management network evidence
// (`networkEvidence`). Every rejection must name what is wrong.
//
// reason and owner must be text, networkEvidence text or a positive integer
// ticket number. Text is a string with at least two different letters or
// digits once blank-rendering characters are removed, not a placeholder
// word (none, null, false, n/a, TBD, ...) and not a number
// written as a string; a numeric string counts only as a positive integer
// ticket number. Keys other than the five fields reject.
//
// History, PR #65 review: the v1.1 gate checked only reason, owner and
// expiry. The first v1.2 gate turned networkEvidence into a string before
// checking its length and measured reason and owner as they were, so null,
// [] and {} passed as evidence and lists, mappings and blank strings as
// reason or owner; a null or non-mapping exception raised a templating
// error. The first v1.3 gate still took any number (0, -5, .nan) and
// zero-width or punctuation-only strings; the second took placeholder words
// (`None`, "null", n/a, TBD), numeric strings ("0", "-5"), one-character
// values and blank-rendering letters (Hangul fillers, U+2800), and ignored
// misspelled keys without a word.
func TestRegression_SnmpInsecureProfileExceptionFields(t *testing.T) {
	day := snmpTestDays(t)
	const expiry = `expiry: "2099-12-31"`
	const valid = `confirmed: true, reason: lab, owner: ops, networkEvidence: "CHG-1", `
	// with returns the valid fields with one replaced: value "" drops it.
	with := func(field, value string) string {
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
	tooLittle := func(field string) []string { return rejects(field + " has too little text") }
	placeholder := func(field, word string) []string {
		return rejects(field + " is the placeholder '" + word + "'")
	}
	const notTicket = "networkEvidence is a number written as a string that is not a positive integer"
	cases := []snmpExceptionCase{
		{"all five fields", snmpValidException + expiry, day(0), nil},
		{"a ticket number as networkEvidence", with("networkEvidence", "1234"), day(0), nil},
		{"a ticket number written as a string", with("networkEvidence", `"0042"`), day(0), nil},
		{"a one-digit ticket number string", with("networkEvidence", `"7"`), day(0), nil},
		{"networkEvidence in another script", with("networkEvidence", `"管理網段 ACL 變更 7"`), day(0), nil},
		{"networkEvidence with a combining accent", with("networkEvidence", `"Cafe\u0301 VLAN"`), day(0), nil},
		{"a two-letter owner", with("owner", "IT"), day(0), nil},
		// YAML 1.1 loads these as the boolean true.
		{"confirmed: yes", with("confirmed", "yes"), day(0), nil},
		{"confirmed: on", with("confirmed", "on"), day(0), nil},
		{"confirmed: True", with("confirmed", "True"), day(0), nil},

		{"confirmed missing", with("confirmed", ""), day(0), rejects("confirmed is missing")},
		{"confirmed false", with("confirmed", "false"), day(0), rejects("confirmed is false, not the boolean true")},
		{"confirmed is the string true", with("confirmed", `"true"`), day(0), rejects("confirmed is a string, not the boolean true")},
		{"confirmed is the string yes", with("confirmed", `"yes"`), day(0), rejects("confirmed is a string, not the boolean true")},
		{"confirmed is 1", with("confirmed", "1"), day(0), rejects("confirmed is a number, not the boolean true")},

		{"networkEvidence missing", with("networkEvidence", ""), day(0), rejects("networkEvidence is missing")},
		{"networkEvidence blank", with("networkEvidence", `"   "`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence null", with("networkEvidence", "null"), day(0), rejects("networkEvidence is null, not text or a ticket number")},
		{"networkEvidence empty list", with("networkEvidence", "[]"), day(0), rejects("networkEvidence is a list, not text or a ticket number")},
		{"networkEvidence empty mapping", with("networkEvidence", "{}"), day(0), rejects("networkEvidence is a mapping, not text or a ticket number")},
		{"networkEvidence list", with("networkEvidence", "[CHG-1]"), day(0), rejects("networkEvidence is a list")},
		{"networkEvidence mapping", with("networkEvidence", "{ticket: CHG-1}"), day(0), rejects("networkEvidence is a mapping")},
		{"networkEvidence boolean", with("networkEvidence", "true"), day(0), rejects("networkEvidence is a boolean")},
		{"networkEvidence written as a bare key", snmpExceptionsVar + `
  lab-v2c:
    confirmed: true
    reason: lab
    owner: ops
    networkEvidence:
    ` + expiry, day(0), rejects("networkEvidence is null")},
		{"networkEvidence zero", with("networkEvidence", "0"), day(0), rejects("networkEvidence is a number that is not a positive integer")},
		{"networkEvidence negative", with("networkEvidence", "-5"), day(0), rejects("networkEvidence is a number that is not a positive integer")},
		{"networkEvidence float", with("networkEvidence", "1.5"), day(0), rejects("networkEvidence is a number, not text or a ticket number")},
		{"networkEvidence NaN", with("networkEvidence", ".nan"), day(0), rejects("networkEvidence is a number, not text")},
		{"networkEvidence infinity", with("networkEvidence", ".inf"), day(0), rejects("networkEvidence is a number, not text")},
		{"networkEvidence tab and newline", with("networkEvidence", `"\t\n"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence no-break space", with("networkEvidence", `"\u00a0"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence ideographic space", with("networkEvidence", `"\u3000"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence zero-width space", with("networkEvidence", `"\u200b"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence punctuation only", with("networkEvidence", `"-"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence underscores only", with("networkEvidence", `"___"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence one character", with("networkEvidence", "x"), day(0), tooLittle("networkEvidence")},
		{"networkEvidence one character repeated", with("networkEvidence", "xxxx"), day(0), tooLittle("networkEvidence")},
		{"networkEvidence Hangul filler", with("networkEvidence", `"\u3164\u3164"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence halfwidth Hangul filler", with("networkEvidence", `"\uffa0\uffa0"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence Hangul choseong and jungseong fillers", with("networkEvidence", `"\u115f\u1160"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence blank Braille pattern", with("networkEvidence", `"\u2800\u2800"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence modifier letters", with("networkEvidence", `"\u02c6\u02c6"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence combining marks only", with("networkEvidence", `"\u0301\u0301"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence one letter and a filler", with("networkEvidence", `"x\u3164"`), day(0), tooLittle("networkEvidence")},
		{"networkEvidence unquoted None", with("networkEvidence", "None"), day(0), placeholder("networkEvidence", "none")},
		{"networkEvidence the string null", with("networkEvidence", `"null"`), day(0), placeholder("networkEvidence", "null")},
		{"networkEvidence n/a", with("networkEvidence", "n/a"), day(0), placeholder("networkEvidence", "na")},
		{"networkEvidence N/A.", with("networkEvidence", `"N/A."`), day(0), placeholder("networkEvidence", "na")},
		{"networkEvidence TBD", with("networkEvidence", "TBD"), day(0), placeholder("networkEvidence", "tbd")},
		{"networkEvidence To-Do", with("networkEvidence", "To-Do"), day(0), placeholder("networkEvidence", "todo")},
		{"networkEvidence the string false", with("networkEvidence", `"false"`), day(0), placeholder("networkEvidence", "false")},
		{"networkEvidence the string .nan", with("networkEvidence", `".nan"`), day(0), placeholder("networkEvidence", "nan")},
		{"networkEvidence the string 0", with("networkEvidence", `"0"`), day(0), rejects(notTicket)},
		{"networkEvidence the string -5", with("networkEvidence", `"-5"`), day(0), rejects(notTicket)},
		{"networkEvidence the string 1.5", with("networkEvidence", `"1.5"`), day(0), rejects(notTicket)},
		{"networkEvidence the string 1e3", with("networkEvidence", `"1e3"`), day(0), rejects(notTicket)},

		{"reason missing", with("reason", ""), day(0), rejects("reason is missing")},
		{"reason blank", with("reason", `"   "`), day(0), tooLittle("reason")},
		{"reason null", with("reason", "null"), day(0), rejects("reason is null, not text")},
		{"reason list", with("reason", "[lab]"), day(0), rejects("reason is a list, not text")},
		{"reason mapping", with("reason", "{why: lab}"), day(0), rejects("reason is a mapping, not text")},
		{"reason number", with("reason", "42"), day(0), rejects("reason is a number, not text")},
		{"reason a number written as a string", with("reason", `"1234"`), day(0), rejects("reason is a number written as a string")},
		{"reason zero-width space", with("reason", `"\u200b"`), day(0), tooLittle("reason")},
		{"reason punctuation only", with("reason", `"---"`), day(0), tooLittle("reason")},
		{"reason unquoted None", with("reason", "None"), day(0), placeholder("reason", "none")},
		{"reason TBD", with("reason", "TBD"), day(0), placeholder("reason", "tbd")},
		{"owner missing", with("owner", ""), day(0), rejects("owner is missing")},
		{"owner blank", with("owner", `"   "`), day(0), tooLittle("owner")},
		{"owner null", with("owner", "null"), day(0), rejects("owner is null, not text")},
		{"owner list", with("owner", "[ops]"), day(0), rejects("owner is a list, not text")},
		{"owner mapping", with("owner", "{team: ops}"), day(0), rejects("owner is a mapping, not text")},
		{"owner zero-width space", with("owner", `"\u200b"`), day(0), tooLittle("owner")},
		{"owner underscore only", with("owner", `"_"`), day(0), tooLittle("owner")},
		{"owner N/A", with("owner", "N/A"), day(0), placeholder("owner", "na")},
		{"owner one character repeated", with("owner", "xx"), day(0), tooLittle("owner")},

		{"an extra key", valid + `comment: hi, ` + expiry, day(0), rejects("unknown key(s) comment")},
		{"a misspelled extra key", valid + `networkevidence: CHG-2, ` + expiry, day(0), rejects("unknown key(s) networkevidence")},
		{"a capitalized extra key", valid + `Confirmed: true, ` + expiry, day(0), rejects("unknown key(s) Confirmed")},
		{"a misspelled field", `confirmed: true, reason: lab, owner: ops, network_evidence: CHG-1, ` + expiry, day(0),
			rejects("unknown key(s) network_evidence", "networkEvidence is missing")},
		{"several fields wrong", `confirmed: 1, reason: [a], owner: {a: b}, networkEvidence: 1.5, network_evidence: x, expiry: null`, day(0),
			rejects("unknown key(s) network_evidence", "confirmed is a number", "reason is a list", "owner is a mapping",
				"networkEvidence is a number", "expiry is not a YYYY-MM-DD calendar date")},
		{"the exception is null", snmpExceptionsVar + "\n  lab-v2c:", day(0), rejects("the exception is null, not a mapping")},
		{"the exception is a list", snmpExceptionsVar + "\n  lab-v2c: [" + strings.TrimSuffix(valid, ", ") + "]", day(0),
			rejects("the exception is a list, not a mapping")},
		{"the exceptions setting is null", snmpExceptionsVar, day(0), rejects("snmp_insecure_auth_profile_exceptions is null, not a mapping")},
		{"the exceptions setting is a string", snmpExceptionsVar + ` '{lab-v2c: {` + strings.TrimSuffix(valid, ", ") + `}}'`, day(0),
			rejects("snmp_insecure_auth_profile_exceptions is a string, not a mapping")},
	}
	runSnmpExceptionCases(t, cases)
}

// TestRegression_SnmpExceptionFromKeyValueExtraVar passes the exceptions as
// -e key=value, which Ansible always reads as a string, even when it looks
// like JSON. The gate must say so instead of reporting a missing exception.
func TestRegression_SnmpExceptionFromKeyValueExtraVar(t *testing.T) {
	gate := snmpExceptionGate(t)
	vars := map[string]any{"stage": "prod", "snmp_catalog_parsed": snmpExceptionProfiles()}
	res := runLocalTasks(t, vars, []map[string]any{gate}, t.TempDir(), nil, "-e",
		`snmp_insecure_auth_profile_exceptions={"lab-v2c":{"confirmed":true,"reason":"lab","owner":"ops","networkEvidence":"CHG-1","expiry":"2099-12-31"}}`)
	checkSnmpGateResult(t, res, rejects("snmp_insecure_auth_profile_exceptions is a string, not a mapping",
		"a value given as -e key=value is always a string"))
}

// TestRegression_SnmpExceptionFromInventory runs the prod gate after the
// pre_task that defaults snmp_insecure_auth_profile_exceptions (PR #74),
// with the exception in group_vars/snmp-exporter.yml, host_vars/localhost.yml
// or an -e file. The default goes through set_fact, which re-templates the
// operator's mapping; the field types the gate checks (a number, null, a
// bare YAML date) must survive that, and an absent setting must still
// reject. host_vars outranks group_vars and -e outranks the set_fact.
func TestRegression_SnmpExceptionFromInventory(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/snmp-exporter-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	const resolveName = "Resolve inventory-overridable defaults without shadowing group_vars/host_vars"
	var tasks []map[string]any
	for _, task := range plays[0]["pre_tasks"].([]any) {
		if m, ok := task.(map[string]any); ok && (m["name"] == resolveName || m["name"] == snmpExceptionGateName) {
			tasks = append(tasks, m)
		}
	}
	if len(tasks) != 2 || tasks[0]["name"] != resolveName {
		t.Fatalf("want %q followed by the gate in pre_tasks, found %d of them", resolveName, len(tasks))
	}
	const fields = `confirmed: true, reason: lab, owner: ops, expiry: 2099-12-31, `
	setting := func(evidence string) string {
		return snmpExceptionsVar + "\n  lab-v2c: {" + fields + "networkEvidence: " + evidence + "}"
	}
	for _, tc := range []struct {
		name                       string
		groupVars, hostVars, extra string
		reject                     []string
	}{
		{"group_vars: a text networkEvidence", setting(`"CHG-1"`), "", "", nil},
		{"group_vars: a ticket number", setting("1234"), "", "", nil},
		{"group_vars: networkEvidence null", setting("null"), "", "", rejects("networkEvidence is null")},
		{"group_vars: networkEvidence empty list", setting("[]"), "", "", rejects("networkEvidence is a list")},
		{"group_vars: networkEvidence zero", setting("0"), "", "", rejects("networkEvidence is a number that is not a positive integer")},
		{"group_vars: the exception null", snmpExceptionsVar + "\n  lab-v2c:", "", "", rejects("the exception is null")},
		{"group_vars: the exceptions setting null", snmpExceptionsVar, "", "", rejects("snmp_insecure_auth_profile_exceptions is null")},
		{"no exceptions setting", "other_var: 1", "", "", rejects("there is no exception for this profile")},
		{"host_vars: a valid exception", "", setting(`"CHG-1"`), "", nil},
		{"host_vars: networkEvidence null", "", setting("null"), "", rejects("networkEvidence is null")},
		{"host_vars over group_vars: valid over null", setting("null"), setting(`"CHG-1"`), "", nil},
		{"host_vars over group_vars: null over valid", setting(`"CHG-1"`), setting("null"), "", rejects("networkEvidence is null")},
		{"-e over the set_fact: valid over null", setting("null"), "", setting(`"CHG-1"`), nil},
		{"-e over the set_fact: null over valid", setting(`"CHG-1"`), "", setting("null"), rejects("networkEvidence is null")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			inv := filepath.Join(dir, "inventory")
			for _, sub := range []string{"group_vars", "host_vars"} {
				if err := os.MkdirAll(filepath.Join(inv, sub), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				"hosts.yml": "snmp-exporter:\n  hosts:\n    localhost: {ansible_connection: local}\n",
			}
			if tc.groupVars != "" {
				files["group_vars/snmp-exporter.yml"] = tc.groupVars + "\n"
			}
			if tc.hostVars != "" {
				files["host_vars/localhost.yml"] = tc.hostVars + "\n"
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(inv, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"-i", filepath.Join(inv, "hosts.yml")}
			if tc.extra != "" {
				extra := filepath.Join(dir, "extra.yml")
				if err := os.WriteFile(extra, []byte(tc.extra+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-e", "@"+extra)
			}
			vars := map[string]any{"stage": "prod", "snmp_catalog_parsed": snmpExceptionProfiles()}
			res := runLocalTasks(t, vars, tasks, dir, nil, args...)
			checkSnmpGateResult(t, res, tc.reject)
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
