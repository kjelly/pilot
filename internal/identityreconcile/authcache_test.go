package identityreconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/gateledger"
)

// The result parser against what the playbooks really wrote and what ansible-playbook
// really printed (AGENTS.md §5.6, §5.12). Every capture under testdata/authcache comes
// from a run on the disposable FreeIPA server and client of the Phase 2 live runs
// (testdata/authcache/README.md says which run, which command and what was changed in
// the text); nothing in them is a format somebody remembered. A rejection test starts
// from a capture and changes one thing in it, so that what it makes fire is the one gate
// it names.

type capture struct {
	stdout, stderr string
	rc             int
	result         []byte
}

func readCapture(t *testing.T, name string) capture {
	t.Helper()
	read := func(ext string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "authcache", name+"."+ext))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c := capture{stdout: string(read("stdout")), stderr: string(read("stderr")), result: nil}
	rc, err := strconv.Atoi(strings.TrimSpace(string(read("rc"))))
	if err != nil {
		t.Fatalf("%s: rc: %v", name, err)
	}
	c.rc = rc
	if b, err := os.ReadFile(filepath.Join("testdata", "authcache", name+".result.json")); err == nil {
		c.result = b
	}
	return c
}

const (
	capturedHost = "ipa-1"
	capturedFQDN = "ipa1.ipa.pilot.internal"
)

func wantFor(action AuthCacheAction) AuthCacheWant {
	return AuthCacheWant{Action: action, Host: capturedHost, FQDN: capturedFQDN}
}

func boolPtr(b bool) *bool { return &b }

// What the real playbooks wrote, parsed: prepare and probe against a journal that is
// absent, owed and settled, and the identity playbook's observation of a run that
// acknowledged, one that did not and why, and one that a tag selection kept from doing
// anything.
func TestParseAuthCacheResultAcceptsTheRealResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action AuthCacheAction
		want   AuthCacheResult // Action, Host and FQDN are filled in
	}{
		{"k16-prepare-absent", AuthCachePrepare, AuthCacheResult{Previous: true}},
		{"k16-prepare-true", AuthCachePrepare, AuthCacheResult{Previous: true}},
		{"k16-prepare-false", AuthCachePrepare, AuthCacheResult{Previous: false}},
		{"k16-probe-absent", AuthCacheProbe, AuthCacheResult{Pending: true}},
		{"k16-probe-true", AuthCacheProbe, AuthCacheResult{Pending: true}},
		{"k16-probe-false", AuthCacheProbe, AuthCacheResult{Pending: false}},
		{"k18-acked-true", AuthCacheObserve, AuthCacheResult{Prepared: true, Dirty: boolPtr(true), Refreshed: true, Acked: true}},
		{"k18-acked-true-rerun", AuthCacheObserve, AuthCacheResult{Prepared: true, Dirty: boolPtr(false), Refreshed: false, Acked: true}},
		{"k18-refresh-off", AuthCacheObserve, AuthCacheResult{Prepared: true, Dirty: boolPtr(true), Refreshed: false, Acked: false}},
		{"k18-deferred-client", AuthCacheObserve, AuthCacheResult{Prepared: true, Dirty: boolPtr(true), Refreshed: false, Acked: false}},
		{"k18-tags-settle-skipped", AuthCacheObserve, AuthCacheResult{Prepared: false, Dirty: nil, Refreshed: false, Acked: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := readCapture(t, tc.name)
			got, err := ParseAuthCacheResult(c.rc, c.result, wantFor(tc.action))
			if err != nil {
				t.Fatalf("a real result was rejected: %v\n%s", err, c.result)
			}
			want := tc.want
			want.Action, want.Host, want.FQDN = tc.action, capturedHost, capturedFQDN
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v (dirty %v), want %+v (dirty %v)", got, deref(got.Dirty), want, deref(want.Dirty))
			}
			// The fqdn is compared without regard to case.
			upper := wantFor(tc.action)
			upper.FQDN = strings.ToUpper(capturedFQDN)
			if _, err := ParseAuthCacheResult(c.rc, c.result, upper); err != nil {
				t.Fatalf("the same result with the FQDN in capitals was rejected: %v", err)
			}
			// What Parse accepts, Render writes and Parse reads back equal (AGENTS.md §5.15),
			// and what Render writes says the same as the playbook did.
			rendered, err := RenderAuthCacheResult(got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseAuthCacheResult(0, rendered, wantFor(tc.action))
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("Parse(Render(x)) = %+v, %v; want %+v", again, err, got)
			}
			var fromPlaybook, fromGo map[string]any
			if err := json.Unmarshal(c.result, &fromPlaybook); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(rendered, &fromGo); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fromPlaybook, fromGo) {
				t.Fatalf("Render writes %s, the playbook wrote %s", rendered, c.result)
			}
		})
	}
}

// mutate changes one thing in a real result, and fails when there was nothing to change:
// a mutation that touches nothing would "pass" for the wrong reason.
func mutate(t *testing.T, result []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(result, []byte(old)) {
		t.Fatalf("the capture has no %q to change:\n%s", old, result)
	}
	return bytes.Replace(result, []byte(old), []byte(new), 1)
}

// Every way ParseAuthCacheResult refuses, each with the gate it fires (the `gate` column,
// checked against the code by TestParseAuthCacheResultEveryGateHasARow). The inputs are
// real captures, either as they are (an exit code and a file ansible-playbook really
// left, the case that must never read as "nothing owed") or with one change.
func TestParseAuthCacheResultRefuses(t *testing.T) {
	prepare := readCapture(t, "k16-prepare-absent")
	probe := readCapture(t, "k16-probe-true")
	observe := readCapture(t, "k18-acked-true")
	prepareOf := func(result []byte) capture { c := prepare; c.result = result; return c }
	probeOf := func(result []byte) capture { c := probe; c.result = result; return c }
	observeOf := func(result []byte) capture { c := observe; c.result = result; return c }

	type row struct {
		name   string
		action AuthCacheAction
		in     capture
		want   *AuthCacheWant // nil: wantFor(action)
		gate   string
		msg    string
	}
	override := func(f func(*AuthCacheWant)) *AuthCacheWant {
		w := wantFor(AuthCachePrepare)
		f(&w)
		return &w
	}
	rows := []row{
		// What ansible-playbook really left, unchanged.
		{name: "exit 0, no host matched: nothing was written", action: AuthCachePrepare, in: readCapture(t, "k16-nohosts-group"), gate: "authcache-empty", msg: "exited 0 without writing"},
		{name: "exit 0, the default group has no host", action: AuthCachePrepare, in: readCapture(t, "k16-nohosts-default-group"), gate: "authcache-empty", msg: "exited 0 without writing"},
		{name: "exit 0, the limit leaves the group empty", action: AuthCachePrepare, in: readCapture(t, "k16-nohosts-limit-outside-group"), gate: "authcache-empty", msg: "exited 0 without writing"},
		{name: "the limit matches no host at all", action: AuthCachePrepare, in: readCapture(t, "k16-nohosts-limit"), gate: "authcache-exit", msg: "exited 1"},
		{name: "a preview", action: AuthCachePrepare, in: readCapture(t, "k16-refuse-checkmode"), gate: "authcache-exit", msg: "exited 2"},
		{name: "a tag selection", action: AuthCachePrepare, in: readCapture(t, "k16-refuse-tags"), gate: "authcache-exit", msg: "exited 2"},
		{name: "two hosts", action: AuthCachePrepare, in: readCapture(t, "k16-refuse-multihost"), gate: "authcache-exit", msg: "exited 2"},
		{name: "the helper failed on another domain", action: AuthCacheProbe, in: readCapture(t, "k16-fail-domain-probe"), gate: "authcache-exit", msg: "exited 2"},
		{name: "the result could not be written", action: AuthCacheProbe, in: readCapture(t, "k17-unwritable-dir"), gate: "authcache-exit", msg: "exited 2"},
		{name: "an observation that was skipped by a preview", action: AuthCacheObserve, in: readCapture(t, "k18-checkmode"), gate: "authcache-empty", msg: "exited 0 without writing"},
		{name: "an observation of a run that was not given a file", action: AuthCacheObserve, in: readCapture(t, "k18-no-output-var"), gate: "authcache-empty", msg: "exited 0 without writing"},
		{name: "an observation of a run that failed early", action: AuthCacheObserve, in: readCapture(t, "k18-earlier-failure"), gate: "authcache-exit", msg: "exited 2"},

		// A good file with a bad exit code: the exit code is not ignored because the file looks fine.
		{name: "a good result of a run that exited 2", action: AuthCachePrepare, in: capture{rc: 2, result: prepare.result}, gate: "authcache-exit", msg: "exited 2"},

		// The question asked.
		{name: "no action asked", action: "", in: prepare, want: override(func(w *AuthCacheWant) { w.Action = "" }), gate: "authcache-want-action", msg: "not one of prepare, probe or observe"},
		{name: "an action nobody runs", action: "settle", in: prepare, want: override(func(w *AuthCacheWant) { w.Action = "settle" }), gate: "authcache-want-action", msg: "not one of prepare, probe or observe"},
		{name: "no locked host", action: AuthCachePrepare, in: prepare, want: override(func(w *AuthCacheWant) { w.Host = "" }), gate: "authcache-want-host", msg: "no locked host"},
		{name: "no FQDN of the locked host", action: AuthCachePrepare, in: prepare, want: override(func(w *AuthCacheWant) { w.FQDN = "" }), gate: "authcache-want-fqdn", msg: "no FQDN"},

		// Whose result it is.
		{name: "a probe result where a prepare was run", action: AuthCachePrepare, in: probe, gate: "authcache-action", msg: `action is "probe", want "prepare"`},
		{name: "a prepare result where a probe was run", action: AuthCacheProbe, in: prepare, gate: "authcache-action", msg: `action is "prepare", want "probe"`},
		{name: "the observation where a prepare was run", action: AuthCachePrepare, in: observe, gate: "authcache-action", msg: `action is "observe", want "prepare"`},
		{name: "another host's result", action: AuthCachePrepare, in: prepare, want: override(func(w *AuthCacheWant) { w.Host = "ipa-2" }), gate: "authcache-host", msg: "another host's result"},
		{name: "the host name in another case is another host", action: AuthCachePrepare, in: prepare, want: override(func(w *AuthCacheWant) { w.Host = "IPA-1" }), gate: "authcache-host", msg: "another host's result"},
		{name: "another server's FQDN", action: AuthCachePrepare, in: prepare, want: override(func(w *AuthCacheWant) { w.FQDN = "ipa2.ipa.pilot.internal" }), gate: "authcache-fqdn", msg: "the locked host reports"},

		// The shape of the file.
		{name: "an empty-looking file", action: AuthCachePrepare, in: prepareOf([]byte("  \n")), gate: "authcache-empty", msg: "is empty"},
		{name: "a file that is not JSON", action: AuthCachePrepare, in: prepareOf([]byte("PLAY RECAP ***")), gate: "authcache-shape", msg: "not JSON"},
		{name: "a JSON list", action: AuthCachePrepare, in: prepareOf([]byte("[1, 2]")), gate: "authcache-shape", msg: "not a JSON object"},
		{name: "a truncated object", action: AuthCachePrepare, in: prepareOf(prepare.result[:len(prepare.result)/2]), gate: "authcache-shape", msg: "not valid JSON"},
		{name: "data after the object", action: AuthCachePrepare, in: prepareOf(append(append([]byte(nil), prepare.result...), []byte(`{"previous": false}`)...)), gate: "authcache-shape", msg: "data after"},
		{name: "a key twice", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"previous": true`, `"previous": false, "previous": true`)), gate: "authcache-shape", msg: `"previous" twice`},
		{name: "a file larger than any result", action: AuthCachePrepare, in: prepareOf(append(bytes.TrimRight(append([]byte(nil), prepare.result...), "\n"), bytes.Repeat([]byte(" "), 17<<10)...)), gate: "authcache-size", msg: "more than the"},

		// The values.
		{name: "schema not a string", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"schema": "pilot.identity-auth-cache/v1"`, `"schema": 1`)), gate: "authcache-schema-type", msg: `"schema" is not a string`},
		{name: "another schema", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, "identity-auth-cache/v1", "identity-auth-cache/v2")), gate: "authcache-schema", msg: "want"},
		{name: "action not a string", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"action": "prepare"`, `"action": 7`)), gate: "authcache-action-type", msg: `"action" is not a string`},
		{name: "a key nobody writes", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"previous": true`, `"previous": true, "extra": true`)), gate: "authcache-unexpected-key", msg: `unexpected key "extra"`},
		{name: "the probe's key in a prepare result", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"previous"`, `"pending"`)), gate: "authcache-unexpected-key", msg: `unexpected key "pending"`},
		{name: "host not a string", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"host": "ipa-1"`, `"host": 1`)), gate: "authcache-host-type", msg: `"host" is not a string`},
		{name: "fqdn not a string", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"fqdn": "`+capturedFQDN+`"`, `"fqdn": null`)), gate: "authcache-fqdn-type", msg: `"fqdn" is not a string`},
		{name: "previous missing", action: AuthCachePrepare, in: prepareOf([]byte(`{"schema": "pilot.identity-auth-cache/v1", "action": "prepare", "host": "ipa-1", "fqdn": "` + capturedFQDN + `"}`)), gate: "authcache-previous", msg: `missing key "previous"`},
		{name: "previous the string true", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"previous": true`, `"previous": "true"`)), gate: "authcache-previous", msg: "not a JSON boolean"},
		{name: "previous null", action: AuthCachePrepare, in: prepareOf(mutate(t, prepare.result, `"previous": true`, `"previous": null`)), gate: "authcache-previous", msg: "not a JSON boolean"},
		{name: "pending the number 1", action: AuthCacheProbe, in: probeOf(mutate(t, probe.result, `"pending": true`, `"pending": 1`)), gate: "authcache-pending", msg: "not a JSON boolean"},
		{name: "pending missing", action: AuthCacheProbe, in: probeOf([]byte(`{"schema": "pilot.identity-auth-cache/v1", "action": "probe", "host": "ipa-1", "fqdn": "` + capturedFQDN + `"}`)), gate: "authcache-pending", msg: `missing key "pending"`},
		{name: "acked the string true", action: AuthCacheObserve, in: observeOf(mutate(t, observe.result, `"acked": true`, `"acked": "true"`)), gate: "authcache-observe-bool", msg: "not a JSON boolean"},
		{name: "prepared missing", action: AuthCacheObserve, in: observeOf(mutate(t, observe.result, `"prepared": true, `, ``)), gate: "authcache-observe-bool", msg: `missing key "prepared"`},
		{name: "dirty missing", action: AuthCacheObserve, in: observeOf(mutate(t, observe.result, `"dirty": true, `, ``)), gate: "authcache-observe-dirty-missing", msg: "no dirty key"},
		{name: "dirty a string", action: AuthCacheObserve, in: observeOf(mutate(t, observe.result, `"dirty": true`, `"dirty": "yes"`)), gate: "authcache-observe-dirty-type", msg: "not a JSON boolean"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			want := wantFor(tc.action)
			if tc.want != nil {
				want = *tc.want
			}
			got, err := ParseAuthCacheResult(tc.in.rc, tc.in.result, want)
			if err == nil {
				t.Fatalf("accepted %+v\nfrom %s (exit %d)", got, tc.in.result, tc.in.rc)
			}
			if !errors.Is(err, ErrAuthCacheResult) {
				t.Fatalf("err = %v does not wrap ErrAuthCacheResult", err)
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %q, want it to say %q (the gate %s)", err, tc.msg, tc.gate)
			}
			if tc.gate == "" {
				t.Fatal("a row names the gate it fires")
			}
		})
	}
}

// Each refusal of ParseAuthCacheResult is named in the code and has a row above that
// fires it, so deleting a gate fails a test and a new one cannot land without a row
// (AGENTS.md §5.12; the scanner is proven in internal/gateledger).
func TestParseAuthCacheResultEveryGateHasARow(t *testing.T) {
	res, err := gateledger.Scan("authcache.go", nil, "ParseAuthCacheResult")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := gateledger.RowGates("authcache_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Returns) < 21 {
		t.Fatalf("found %d gates in ParseAuthCacheResult, want at least the 21 it had", len(res.Returns))
	}
	for _, p := range gateledger.Check(res, rows, nil) {
		t.Error(p)
	}
}

// The captures are what they are said to be. A parser test that starts from a capture is
// only as good as the capture, so the facts the spec relies on are pinned here against the
// raw output: ansible-playbook exits 0 and writes nothing when no host matches; a limit
// that matches no host at all is an error; a preview, a tag selection, a second host, an
// unknown action and a failing helper are refused with the exit code 2 and no result; and
// what `ansible <pattern> --list-hosts` prints for an empty, one-host and two-host match.
func TestAuthCacheCapturesShowWhatTheSpecRelaysOn(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rc         int
		stdout     []string // all of them in stdout
		stderr     []string
		noResult   bool
		notInStdio []string
	}{
		{name: "k16-nohosts-group", rc: 0, stdout: []string{"skipping: no hosts matched"}, stderr: []string{"Could not match supplied host pattern, ignoring: no-such-group"}, noResult: true, notInStdio: []string{"TASK ["}},
		{name: "k16-nohosts-default-group", rc: 0, stdout: []string{"skipping: no hosts matched"}, noResult: true, notInStdio: []string{"TASK ["}},
		{name: "k16-nohosts-limit-outside-group", rc: 0, stdout: []string{"skipping: no hosts matched"}, noResult: true, notInStdio: []string{"TASK ["}},
		{name: "k16-nohosts-limit", rc: 1, stderr: []string{"leaves us with no hosts to target"}, noResult: true},
		{name: "k16-refuse-checkmode", rc: 2, stdout: []string{"does not run in check mode", "fatal:"}, noResult: true, notInStdio: []string{"Read the host's FQDN"}},
		{name: "k16-refuse-tags", rc: 2, stdout: []string{"takes no --tags and no --skip-tags", "fatal:"}, noResult: true},
		{name: "k16-refuse-skip-tags", rc: 2, stdout: []string{"takes no --tags and no --skip-tags", "fatal:"}, noResult: true},
		{name: "k16-refuse-multihost", rc: 2, stdout: []string{"is for exactly one host", "got 2"}, noResult: true},
		{name: "k16-refuse-no-action", rc: 2, stdout: []string{"must be prepare or probe"}, noResult: true},
		{name: "k16-refuse-bad-action", rc: 2, stdout: []string{"must be prepare or probe"}, noResult: true},
		{name: "k16-refuse-relative-output", rc: 2, stdout: []string{"absolute path"}, noResult: true},
		{name: "k16-refuse-no-output", rc: 2, stdout: []string{"absolute path"}, noResult: true},
		{name: "k16-refuse-stage-mismatch", rc: 2, stdout: []string{"inventory 環境 group 不一致"}, noResult: true},
		{name: "k16-fail-domain-prepare", rc: 2, stdout: []string{"journal domain mismatch", "non-zero return code"}, noResult: true},
		{name: "k16-fail-domain-probe", rc: 2, stdout: []string{"journal domain mismatch", "non-zero return code"}, noResult: true},
		{name: "k16-fail-damaged-probe", rc: 2, stdout: []string{"non-zero return code"}, noResult: true},
		{name: "k17-unwritable-dir", rc: 2, stdout: []string{"not writable", "Write the result for pilot (on the controller)"}, noResult: true},
		{name: "k17-dest-missing-dir", rc: 2, stdout: []string{"Destination directory <out>/no-such-dir does not exist", "Write the result for pilot (on the controller)"}, noResult: true},
		{name: "k17-dest-is-a-directory", rc: 2, stdout: []string{"can not use content with a dir as dest", "Write the result for pilot (on the controller)"}, noResult: true},
		{name: "k18-checkmode", rc: 0, stdout: []string{"Record what this run did about the authorization cache (observation for pilot)", "skipping:"}, noResult: true},
		{name: "k18-no-output-var", rc: 0, stdout: []string{"Record what this run did about the authorization cache (observation for pilot)", "skipping:"}, noResult: true},
		{name: "k18-earlier-failure", rc: 2, stdout: []string{"fatal:"}, noResult: true, notInStdio: []string{"Record what this run did about the authorization cache"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := readCapture(t, tc.name)
			if c.rc != tc.rc {
				t.Errorf("exit code %d, want %d", c.rc, tc.rc)
			}
			for _, want := range tc.stdout {
				if !strings.Contains(c.stdout, want) {
					t.Errorf("stdout has no %q:\n%s", want, c.stdout)
				}
			}
			for _, want := range tc.stderr {
				if !strings.Contains(c.stderr, want) {
					t.Errorf("stderr has no %q:\n%s", want, c.stderr)
				}
			}
			for _, not := range tc.notInStdio {
				if strings.Contains(c.stdout, not) {
					t.Errorf("stdout has %q, which a run of this kind never reaches", not)
				}
			}
			if tc.noResult && len(bytes.TrimSpace(c.result)) != 0 {
				t.Errorf("the result file holds %q", c.result)
			}
		})
	}

	// ansible <pattern> --list-hosts, the way deploy resolves the hosts of a play.
	for _, tc := range []struct {
		name   string
		rc     int
		stdout string
		stderr []string
	}{
		{"k16-listhosts-empty-group", 0, "  hosts (0):\n", []string{"Could not match supplied host pattern, ignoring: freeipa-server-replica", "No hosts matched, nothing to do"}},
		{"k16-listhosts-empty-limit", 1, "", []string{"leaves us with no hosts to target"}},
		{"k16-listhosts-unknown-limit", 1, "", []string{"Could not match supplied host pattern, ignoring: no-such-host", "leaves us with no hosts to target"}},
		{"k16-listhosts-one", 0, "  hosts (1):\n    ipa-1\n", nil},
		{"k16-listhosts-multi", 0, "  hosts (2):\n    client-1\n    ipa-1\n", nil},
		{"k16-listhosts-multi-limited-to-one", 0, "  hosts (1):\n    ipa-1\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := readCapture(t, tc.name)
			if c.rc != tc.rc || c.stdout != tc.stdout {
				t.Errorf("exit %d, stdout %q; want exit %d, stdout %q", c.rc, c.stdout, tc.rc, tc.stdout)
			}
			for _, want := range tc.stderr {
				if !strings.Contains(c.stderr, want) {
					t.Errorf("stderr has no %q:\n%s", want, c.stderr)
				}
			}
		})
	}
}

// No capture carries a secret, a lab host name or a lab address: the identifiers of the
// lab were replaced when the files were made (testdata/authcache/README.md), and the
// secrets never printed (the entry and the observation hold none, and no_log covers the
// identity playbook's). Checked the way that does not name what must not be there: every
// host a play line or a recap line mentions is one of the replacement names, no address is
// outside the documentation range, and none of the paths or names of a secret is present.
func TestAuthCacheCapturesHoldNoLabIdentifiersOrSecrets(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "authcache"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 60 {
		t.Fatalf("%d capture files: the K16-K18 set is missing", len(entries))
	}
	hostOfLine := regexp.MustCompile(`^(?:ok|changed|skipping|fatal|failed|unreachable|included): \[([^\] ]+)|^([A-Za-z0-9._-]+)\s+: ok=\d+`)
	address := regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\b`)
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join("testdata", "authcache", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			if m := hostOfLine.FindStringSubmatch(line); m != nil {
				host := m[1] + m[2]
				if host != "ipa-1" && host != "client-1" && host != "localhost" && host != "" {
					t.Errorf("%s: a line names the host %q: %s", e.Name(), host, line)
				}
			}
			for _, m := range address.FindAllStringSubmatch(line, -1) {
				if m[1] != "192" || m[2] != "0" || m[3] != "2" {
					t.Errorf("%s: an address outside 192.0.2.0/24: %s", e.Name(), m[0])
				}
			}
		}
		for _, bad := range []string{"/home/", "/tmp/claude", "libvirt", "ipa_admin_password", "vault-pass", "BEGIN ", "ipa_session", "Authorization:", "Cookie:", "krbprincipalkey", "ipanthash", "userpassword"} {
			if strings.Contains(string(body), bad) {
				t.Errorf("%s contains %q", e.Name(), bad)
			}
		}
	}
}

// The result file of a run: made empty and private, made empty again for the next run
// whatever the last one left (a file, a symlink, a directory), read only if it is a small
// regular file, and handed to ansible-playbook in the form that survives a space.
func TestAuthCacheOutput(t *testing.T) {
	out, err := NewAuthCacheOutput()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	info, err := os.Stat(out.path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		t.Fatalf("the result file: %v, %v: want an empty 0600 file", info, err)
	}
	if dir, err := os.Stat(filepath.Dir(out.path)); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v, %v: want 0700", dir, err)
	}
	if !filepath.IsAbs(out.path) {
		t.Fatalf("path %q is not absolute: the playbook refuses a relative one", out.path)
	}

	// A run writes; the next one starts from an empty file, a new file.
	if err := os.WriteFile(out.path, []byte(`{"stale": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(out.path)
	if err := out.reset(); err != nil {
		t.Fatal(err)
	}
	if got, err := out.read(); err != nil || len(got) != 0 {
		t.Fatalf("after reset: %q, %v", got, err)
	}
	if after, _ := os.Stat(out.path); os.SameFile(before, after) {
		t.Fatal("reset reused the file: a process that kept it open could still write into the next run's result")
	}

	// A symlink put in its place is replaced, not followed; a directory too is replaced.
	secret := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(secret, []byte(`{"from": "elsewhere"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(out.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, out.path); err != nil {
		t.Fatal(err)
	}
	if _, err := out.read(); !errors.Is(err, ErrAuthCacheResult) {
		t.Fatalf("read of a symlink: %v, want a rejection", err)
	}
	if err := out.reset(); err != nil {
		t.Fatal(err)
	}
	if got, err := out.read(); err != nil || len(got) != 0 {
		t.Fatalf("after reset over a symlink: %q, %v", got, err)
	}
	if kept, _ := os.ReadFile(secret); string(kept) != `{"from": "elsewhere"}` {
		t.Fatalf("reset wrote through the symlink: %q", kept)
	}

	// Oversize is refused before it is read.
	if err := os.WriteFile(out.path, bytes.Repeat([]byte("x"), 17<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := out.read(); !errors.Is(err, ErrAuthCacheResult) {
		t.Fatalf("read of a 17 KiB file: %v, want a rejection", err)
	}

	// The extra variables: the JSON object form, so a space in the path is kept (key=value
	// would be split at the blank by Ansible, found when the same was done for -e elsewhere).
	spaced := &AuthCacheOutput{path: "/tmp/with space/result.json"}
	encoded, err := spaced.extraVars(AuthCacheProbe)
	if err != nil {
		t.Fatal(err)
	}
	var vars map[string]string
	if err := json.Unmarshal([]byte(encoded), &vars); err != nil {
		t.Fatalf("%s: %v", encoded, err)
	}
	if vars[AuthCacheOutputVar] != spaced.path || vars[AuthCacheActionVar] != "probe" || len(vars) != 2 {
		t.Fatalf("extra vars %v", vars)
	}
	encoded, err = spaced.extraVars("")
	if err != nil || strings.Contains(encoded, AuthCacheActionVar) {
		t.Fatalf("the observation takes no action variable: %s, %v", encoded, err)
	}

	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close left the result file: %v", err)
	}
}

// The reset cannot be skipped (P2-3 review): Run is the one way to run a playbook
// that writes the file, it resets before it runs, and the type offers nothing else
// to call. These rows are the discriminating ones: the same stale result that a
// caller who forgot the reset would read back as its own.

func authCacheWant() AuthCacheWant {
	return AuthCacheWant{Action: AuthCachePrepare, Host: "ipa-1", FQDN: "ipa-1.example.test"}
}

var staleAndPlausible = []byte(`{"schema":"pilot.identity-auth-cache/v1","action":"prepare","host":"ipa-1","fqdn":"ipa-1.example.test","previous":false}`)

func newOutput(t *testing.T) *AuthCacheOutput {
	t.Helper()
	out, err := NewAuthCacheOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func TestAuthCacheOutputRunResetsBeforeEveryRun(t *testing.T) {
	out := newOutput(t)
	// An earlier run left a result that is valid for this host: `previous: false`
	// reads as "nothing was owed", the dangerous answer.
	if err := os.WriteFile(out.path, staleAndPlausible, 0o600); err != nil {
		t.Fatal(err)
	}
	stale, _ := os.Stat(out.path)
	var sawEmpty, sawNewFile bool
	_, err := out.Run(context.Background(), authCacheWant(), func(_ context.Context, vars string) (int, error) {
		info, serr := os.Stat(out.path)
		data, _ := os.ReadFile(out.path)
		sawEmpty = serr == nil && len(data) == 0
		sawNewFile = serr == nil && !os.SameFile(stale, info)
		return 0, nil // ansible-playbook exits 0 and writes nothing (no host matched)
	})
	if !sawEmpty || !sawNewFile {
		t.Fatalf("the playbook found the file empty: %v, a new file: %v; the earlier run's result was still there", sawEmpty, sawNewFile)
	}
	if !errors.Is(err, ErrAuthCacheResult) || !strings.Contains(err.Error(), "the result file is empty") {
		t.Fatalf("err = %v: a run that wrote nothing must read as an entry failure, not as the earlier run's result", err)
	}
}

func TestAuthCacheOutputRunHandsTheVariablesAndReturnsWhatTheRunWrote(t *testing.T) {
	out := newOutput(t)
	var seen map[string]string
	res, err := out.Run(context.Background(), authCacheWant(), func(_ context.Context, vars string) (int, error) {
		if err := json.Unmarshal([]byte(vars), &seen); err != nil {
			return 0, err
		}
		return 0, os.WriteFile(seen[AuthCacheOutputVar], staleAndPlausible, 0o600)
	})
	if err != nil || res.Action != AuthCachePrepare || res.Previous {
		t.Fatalf("result %+v, %v", res, err)
	}
	if seen[AuthCacheActionVar] != "prepare" || seen[AuthCacheOutputVar] != out.path || len(seen) != 2 {
		t.Fatalf("extra vars %v", seen)
	}
	// The observation is the identity playbook's own: no action variable.
	obs, err := out.Run(context.Background(), AuthCacheWant{Action: AuthCacheObserve, Host: "ipa-1", FQDN: "ipa-1.example.test"}, func(_ context.Context, vars string) (int, error) {
		seen = nil
		if err := json.Unmarshal([]byte(vars), &seen); err != nil {
			return 0, err
		}
		return 0, os.WriteFile(seen[AuthCacheOutputVar], []byte(`{"schema":"pilot.identity-auth-cache/v1","action":"observe","host":"ipa-1","fqdn":"ipa-1.example.test","prepared":true,"dirty":null,"refreshed":false,"acked":true}`), 0o600)
	})
	if err != nil || !obs.Acked || obs.Dirty != nil {
		t.Fatalf("observe %+v, %v", obs, err)
	}
	if _, has := seen[AuthCacheActionVar]; has || len(seen) != 1 {
		t.Fatalf("the observation's extra vars %v", seen)
	}
	// A run after it starts from nothing, and reads only what it wrote itself.
	if _, err := out.Run(context.Background(), authCacheWant(), func(context.Context, string) (int, error) { return 0, nil }); !errors.Is(err, ErrAuthCacheResult) {
		t.Fatalf("a run after a run that wrote: %v, want the empty file rejected", err)
	}
}

func TestAuthCacheOutputRunRefusesWhatTheRunDid(t *testing.T) {
	out := newOutput(t)
	write := func(vars string) {
		var m map[string]string
		_ = json.Unmarshal([]byte(vars), &m)
		_ = os.WriteFile(m[AuthCacheOutputVar], staleAndPlausible, 0o600)
	}
	// ansible-playbook failed: a result it wrote before failing is not accepted.
	if _, err := out.Run(context.Background(), authCacheWant(), func(_ context.Context, vars string) (int, error) { write(vars); return 2, nil }); !errors.Is(err, ErrAuthCacheResult) || !strings.Contains(err.Error(), "exited 2") {
		t.Fatalf("a failed run: %v", err)
	}
	// It could not be started: the error is its own, not a parse rejection.
	boom := errors.New("no ansible-playbook")
	if _, err := out.Run(context.Background(), authCacheWant(), func(context.Context, string) (int, error) { return 0, boom }); !errors.Is(err, boom) || errors.Is(err, ErrAuthCacheResult) {
		t.Fatalf("a run that did not start: %v", err)
	}
	// Something else put a symlink where the file is, during the run.
	secret := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(secret, staleAndPlausible, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Run(context.Background(), authCacheWant(), func(context.Context, string) (int, error) {
		_ = os.Remove(out.path)
		return 0, os.Symlink(secret, out.path)
	}); !errors.Is(err, ErrAuthCacheResult) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a symlink put in its place during the run: %v", err)
	}
	// And a run that wrote the wrong host's result is rejected as before.
	if _, err := out.Run(context.Background(), AuthCacheWant{Action: AuthCachePrepare, Host: "ipa-2", FQDN: "ipa-1.example.test"}, func(_ context.Context, vars string) (int, error) {
		write(vars)
		return 0, nil
	}); !errors.Is(err, ErrAuthCacheResult) || !strings.Contains(err.Error(), "another host's result") {
		t.Fatalf("another host's result: %v", err)
	}
}

// Two runs do not overlap: the second would reset the file under the first.
func TestAuthCacheOutputRunsOneAtATime(t *testing.T) {
	out := newOutput(t)
	var inside, most atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = out.Run(context.Background(), authCacheWant(), func(context.Context, string) (int, error) {
				n := inside.Add(1)
				for {
					m := most.Load()
					if n <= m || most.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(2 * time.Millisecond)
				inside.Add(-1)
				return 0, nil
			})
		}()
	}
	wg.Wait()
	if most.Load() != 1 {
		t.Fatalf("%d runs overlapped", most.Load())
	}
}

// The type offers Run and Close and nothing a caller could use to skip the reset:
// no exported Reset, Read or ExtraVars, no exported path. A new exported method or
// field must be added to the list on purpose, with the reason it cannot skip it.
func TestAuthCacheOutputOffersOnlyRun(t *testing.T) {
	typ := reflect.TypeOf(&AuthCacheOutput{})
	var methods []string
	for i := 0; i < typ.NumMethod(); i++ {
		methods = append(methods, typ.Method(i).Name)
	}
	if want := []string{"Close", "Run"}; !slices.Equal(methods, want) {
		t.Fatalf("exported methods = %v, want %v", methods, want)
	}
	elem := typ.Elem()
	for i := 0; i < elem.NumField(); i++ {
		if elem.Field(i).IsExported() {
			t.Fatalf("exported field %s: a caller could read the path and run without Run", elem.Field(i).Name)
		}
	}
}
