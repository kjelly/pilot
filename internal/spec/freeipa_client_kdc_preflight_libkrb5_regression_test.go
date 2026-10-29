package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// GitHub issue #168 follow-up (PR #180 review, finding B and the matching
// parse questions): the KDC names the preflight probes must be the ones
// libkrb5 would look up. libkrb5 decodes a profile value (a quoted string is
// unescaped and anything after the closing quote is dropped; `#` and `;` are
// NOT comments inside a value), cuts the host at the first whitespace, and
// then splits host:port / [v6]:port / https://host[:port]/path. These tests
// check the probe against testdata/kdc-preflight/libkrb5-kdc-values.json (a
// real capture from MIT libkrb5: the decoded profile value and the first host
// kinit resolved, from KRB5_TRACE), and against a live kinit when one is on
// PATH.

const libkrb5KDCValuesFixture = "testdata/kdc-preflight/libkrb5-kdc-values.json"

type libkrb5KDCRow struct {
	Name       string   `json:"name"`
	Raw        string   `json:"raw"`
	Decoded    []string `json:"decoded"`
	FirstHost  string   `json:"first_host"`
	KinitError string   `json:"kinit_error"`
}

type libkrb5KDCFixture struct {
	CapturedWith string          `json:"captured_with"`
	Method       string          `json:"method"`
	NotVerified  string          `json:"not_verified_on"`
	Rows         []libkrb5KDCRow `json:"rows"`
}

func loadLibkrb5KDCFixture(t *testing.T) libkrb5KDCFixture {
	t.Helper()
	raw, err := os.ReadFile(libkrb5KDCValuesFixture)
	if err != nil {
		t.Fatal(err)
	}
	var fx libkrb5KDCFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("%s: %v", libkrb5KDCValuesFixture, err)
	}
	return fx
}

// probeKDCConf runs the real probe over a krb5.conf body (no resolvectl).
func probeKDCConf(t *testing.T, body string, extra map[string]any) kdcProbeResult {
	t.Helper()
	conf := writeKDCFile(t, t.TempDir(), "krb5.conf", body)
	in := map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""}
	for k, v := range extra {
		in[k] = v
	}
	return runKDCProbe(t, in)
}

func isIPText(s string) bool { return net.ParseIP(strings.Split(s, "%")[0]) != nil }

// TestRegression_KDCPreflightFixtureIsHonestlyLabelled keeps the section 5.6
// rule for the libkrb5 capture: it says which libkrb5 produced it and what it
// was not run on, every row has the real decoded value, and the rows that
// libkrb5 rejects carry the error kinit printed.
func TestRegression_KDCPreflightFixtureIsHonestlyLabelled(t *testing.T) {
	fx := loadLibkrb5KDCFixture(t)
	if !regexp.MustCompile(`^Kerberos 5 release 1\.\d+(\.\d+)?$`).MatchString(fx.CapturedWith) {
		t.Errorf("captured_with = %q must name the libkrb5 release that produced the rows", fx.CapturedWith)
	}
	if !strings.Contains(fx.NotVerified, "not run") || !strings.Contains(fx.Method, "KRB5_TRACE") {
		t.Errorf("the fixture must say how it was captured and what it was not verified on: %+v", fx)
	}
	rejected, accepted := 0, 0
	for _, r := range fx.Rows {
		if len(r.Decoded) != 1 {
			t.Errorf("%s: libkrb5 returned %d decoded values, want 1", r.Name, len(r.Decoded))
		}
		if r.FirstHost == "" {
			rejected++
			if r.KinitError != "Invalid argument" {
				t.Errorf("%s: a rejected value must carry kinit's error, got %q", r.Name, r.KinitError)
			}
		} else {
			accepted++
		}
	}
	if accepted < 20 || rejected < 8 {
		t.Errorf("fixture shrank: accepted=%d rejected=%d", accepted, rejected)
	}
}

// TestRegression_KDCPreflightKDCNamesMatchLibkrb5 is the table test: for every
// captured form the probe's kdc_names must be exactly the host libkrb5 looked
// up (lower-cased, trailing dot dropped), an IP-literal KDC must not be
// probed as a name, and a value libkrb5 rejects must land in `unparsable`
// instead of being probed under a made-up name.
func TestRegression_KDCPreflightKDCNamesMatchLibkrb5(t *testing.T) {
	requirePython3ForKDCTests(t)
	fx := loadLibkrb5KDCFixture(t)
	for _, r := range fx.Rows {
		t.Run(r.Name, func(t *testing.T) {
			res := probeKDCConf(t, krb5Realm("kdc = "+r.Raw), nil)
			switch {
			case r.FirstHost == "":
				if len(res.KDCNames) != 0 || len(res.Names) != 0 {
					t.Errorf("libkrb5 rejects %q (%s); the probe must not resolve any name for it: kdc=%v names=%v", r.Raw, r.KinitError, res.KDCNames, res.Names)
				}
				if len(res.Unparsable) != 1 || res.Unparsable[0] != r.Raw {
					t.Errorf("unparsable = %q, want [%q]", res.Unparsable, r.Raw)
				}
				if res.KDCUnusable {
					t.Errorf("a rejected value is reported as unparsable, not as an unresolvable KDC: %+v", res)
				}
			case isIPText(r.FirstHost):
				if len(res.KDCNames) != 0 || len(res.Names) != 0 || len(res.Unparsable) != 0 {
					t.Errorf("an IP-literal KDC (%s) needs no resolution: %+v", r.FirstHost, res)
				}
			default:
				want := strings.ToLower(strings.TrimRight(r.FirstHost, "."))
				if !sameSet(res.KDCNames, []string{want}) {
					t.Errorf("kdc_names = %q, libkrb5 looked up %q (raw %q)", res.KDCNames, r.FirstHost, r.Raw)
				}
				if len(res.Unparsable) != 0 {
					t.Errorf("libkrb5 accepts %q, the probe reports it unparsable: %q", r.Raw, res.Unparsable)
				}
			}
		})
	}
}

// TestRegression_KDCPreflightQuotedValueEqualsPlain is the finding B pair: a
// valid quoted profile string must give the same answer as the unquoted one.
func TestRegression_KDCPreflightQuotedValueEqualsPlain(t *testing.T) {
	requirePython3ForKDCTests(t)
	plain := probeKDCConf(t, krb5Realm("kdc = localhost:88"), nil)
	for _, v := range []string{`"localhost:88"`, `"localhost":88`, `"localhost"`, `  "localhost:88"  `} {
		got := probeKDCConf(t, krb5Realm("kdc = "+v), nil)
		if !sameSet(got.KDCNames, plain.KDCNames) || !sameSet(got.Resolved, plain.Resolved) ||
			!sameSet(got.Unresolved, plain.Unresolved) || got.KDCUnusable != plain.KDCUnusable ||
			!sameSet(got.RequiredUnresolved, plain.RequiredUnresolved) {
			t.Errorf("kdc = %s differs from the plain form:\nquoted: %+v\nplain:  %+v", v, got, plain)
		}
	}
	if !sameSet(plain.Resolved, []string{"localhost"}) || plain.KDCUnusable {
		t.Fatalf("the control must resolve: %+v", plain)
	}

	// A quoted name that does not resolve is reported by its decoded name, not
	// with a leading quote.
	const bad = "quoted.pilot168.invalid"
	res := probeKDCConf(t, krb5Realm(`kdc = "`+bad+`:88"`), nil)
	if !sameSet(res.Unresolved, []string{bad}) || !sameSet(res.KDCNames, []string{bad}) {
		t.Fatalf("want the decoded name %s unresolved, got %+v", bad, res)
	}
	for _, n := range res.Names {
		if strings.ContainsAny(n, `"`) {
			t.Errorf("name %q still carries a quote", n)
		}
	}
}

// TestRegression_KDCPreflightMasterKDCIsNotAKDC: libkrb5 does not use
// master_kdc for the initial AS exchange, so a resolvable master_kdc must not
// hide an unusable kdc list, and an unresolvable master_kdc must not make a
// working one required.
func TestRegression_KDCPreflightMasterKDCIsNotAKDC(t *testing.T) {
	requirePython3ForKDCTests(t)
	const bad = "ipa1.pilot168.invalid"
	t.Run("resolvable master_kdc does not mask a dead kdc", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm("kdc = "+bad+":88", "master_kdc = localhost:88"), nil)
		if !res.KDCUnusable || !sameSet(res.RequiredUnresolved, []string{bad}) || !sameSet(res.KDCNames, []string{bad}) {
			t.Fatalf("master_kdc must not count as a KDC: %+v", res)
		}
	})
	t.Run("unresolvable master_kdc does not condemn a working kdc", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm("kdc = localhost:88", "master_kdc = "+bad+":88"), nil)
		if res.KDCUnusable || len(res.RequiredUnresolved) != 0 {
			t.Fatalf("a working kdc is enough: %+v", res)
		}
		if !sameSet(res.Unresolved, []string{bad}) {
			t.Errorf("the stale master_kdc is still reported: %+v", res)
		}
	})
	t.Run("master_kdc alone is not a KDC list", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm("master_kdc = "+bad+":88"), nil)
		if res.KDCUnusable || len(res.KDCNames) != 0 {
			t.Fatalf("%+v", res)
		}
	})
}

// TestRegression_KDCPreflightKDCUnusable locks the new `kdc_unusable` and
// `admin_unresolved` outputs the state machine reads: unusable only when kdc
// names exist, none is an IP literal, and none resolves.
func TestRegression_KDCPreflightKDCUnusable(t *testing.T) {
	requirePython3ForKDCTests(t)
	const bad1, bad2 = "ipa1.pilot168.invalid", "ipa2.pilot168.invalid"
	for _, tc := range []struct {
		name      string
		relations []string
		extra     map[string]any
		unusable  bool
		required  []string
		admin     []string
	}{
		{"every name unresolved: unusable (trigger)", []string{"kdc = " + bad1, "kdc = " + bad2}, nil, true, []string{bad1, bad2}, nil},
		{"mixed: one resolves (pass)", []string{"kdc = localhost", "kdc = " + bad2}, nil, false, nil, nil},
		{"an IP-literal KDC keeps the names optional (pass)", []string{"kdc = 192.0.2.10:88", "kdc = " + bad1}, nil, false, nil, nil},
		{"a bracketed IPv6 KDC keeps the names optional (pass)", []string{"kdc = [2001:db8::10]:88", "kdc = " + bad1}, nil, false, nil, nil},
		{"no kdc relation at all (pass)", []string{"admin_server = " + bad1}, nil, false, nil, nil},
		{"all resolvable (pass)", []string{"kdc = localhost"}, nil, false, nil, nil},
		{"unusable plus an unresolved admin endpoint (trigger)", []string{"kdc = " + bad1}, map[string]any{"required_names": []string{bad2}}, true, []string{bad1, bad2}, []string{bad2}},
		{"usable, admin endpoint unresolved (trigger)", []string{"kdc = localhost"}, map[string]any{"required_names": []string{"IPA2.Pilot168.invalid."}}, false, []string{bad2}, []string{bad2}},
		{"usable, admin endpoint resolves (pass)", []string{"kdc = localhost"}, map[string]any{"required_names": []string{"localhost"}}, false, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := probeKDCConf(t, krb5Realm(tc.relations...), tc.extra)
			if res.KDCUnusable != tc.unusable {
				t.Errorf("kdc_unusable = %v, want %v: %+v", res.KDCUnusable, tc.unusable, res)
			}
			if !sameSet(res.RequiredUnresolved, tc.required) {
				t.Errorf("required_unresolved = %v, want %v", res.RequiredUnresolved, tc.required)
			}
			if !sameSet(res.AdminUnresolved, tc.admin) {
				t.Errorf("admin_unresolved = %v, want %v", res.AdminUnresolved, tc.admin)
			}
		})
	}
}

// TestRegression_KDCPreflightProfileSyntax locks the krb5.conf profile-layer
// rules that decide which relations belong to the realm stanza (each one
// verified against libkrb5's profile_get_values): a subsection opener is a
// value that is exactly `{`, a closer is a line that starts with `}`, an
// includedir skips dot-files, and include/section lines are only recognised
// at column 0.
func TestRegression_KDCPreflightProfileSyntax(t *testing.T) {
	requirePython3ForKDCTests(t)
	const hsub = "hsub.pilot168.invalid"
	t.Run("a value that merely ends in a brace is an ordinary value", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm("kdc = h1.pilot168.invalid{", "kdc = localhost"), nil)
		if !sameSet(res.KDCNames, []string{"h1.pilot168.invalid{", "localhost"}) {
			t.Fatalf("the later kdc line must still be read: %+v", res)
		}
	})
	t.Run("a closing brace may carry a trailing comment or junk", func(t *testing.T) {
		for _, closer := range []string{"} # c", "} junk", "}"} {
			res := probeKDCConf(t, krb5Realm("sub = {", "kdc = "+hsub, closer, "kdc = localhost"), nil)
			if !sameSet(res.KDCNames, []string{"localhost"}) {
				t.Errorf("closer %q: kdc_names = %v, want only the relation after the subsection", closer, res.KDCNames)
			}
		}
	})
	t.Run("a subsection with a quoted name and a brace on its own line", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm(`"sub" = {`, "kdc = "+hsub, "}", "other =", "{", "kdc = "+hsub, "}", "kdc = localhost"), nil)
		if !sameSet(res.KDCNames, []string{"localhost"}) {
			t.Fatalf("kdc_names = %v", res.KDCNames)
		}
	})
	t.Run("a relation in a subsection is not a realm relation", func(t *testing.T) {
		res := probeKDCConf(t, krb5Realm("sub = {", "kdc = "+hsub, "}"), nil)
		if len(res.KDCNames) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("includedir: dot-files are skipped, *.conf and bare names are read", func(t *testing.T) {
		dir := t.TempDir()
		confd := filepath.Join(dir, "krb5.conf.d")
		writeKDCFile(t, dir, "krb5.conf", "includedir "+confd+"\n[libdefaults]\n default_realm = IPA.PILOT.INTERNAL\n")
		stanza := func(h string) string {
			return "[realms]\n IPA.PILOT.INTERNAL = {\n  kdc = " + h + "\n }\n"
		}
		writeKDCFile(t, confd, "a.conf", stanza("from-a-conf"))
		writeKDCFile(t, confd, "freeipa-realm", stanza("from-freeipa-realm"))
		writeKDCFile(t, confd, ".hidden.conf", stanza("from-hidden"))
		writeKDCFile(t, confd, "b.bak", stanza("from-bak"))
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{filepath.Join(dir, "krb5.conf")}, "resolvectl": ""})
		if !sameSet(res.KDCNames, []string{"from-a-conf", "from-freeipa-realm"}) {
			t.Fatalf("kdc_names = %v", res.KDCNames)
		}
	})
	t.Run("an indented include and an indented section header are not recognised", func(t *testing.T) {
		dir := t.TempDir()
		inc := writeKDCFile(t, dir, "inc.conf", "[realms]\n IPA.PILOT.INTERNAL = {\n  kdc = from-indented-include\n }\n")
		mainConf := writeKDCFile(t, dir, "krb5.conf", "  include "+inc+"\n  [realms]\n IPA.PILOT.INTERNAL = {\n  kdc = from-indented-section\n }\n")
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{mainConf}, "resolvectl": ""})
		if len(res.KDCNames) != 0 {
			t.Fatalf("libkrb5 ignores both; kdc_names = %v", res.KDCNames)
		}
	})
	t.Run("a column-0 include is followed", func(t *testing.T) {
		dir := t.TempDir()
		inc := writeKDCFile(t, dir, "inc.conf", "[realms]\n IPA.PILOT.INTERNAL = {\n  kdc = from-include\n }\n")
		mainConf := writeKDCFile(t, dir, "krb5.conf", "include "+inc+"\n")
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{mainConf}, "resolvectl": ""})
		if !sameSet(res.KDCNames, []string{"from-include"}) {
			t.Fatalf("kdc_names = %v", res.KDCNames)
		}
	})
	t.Run("a non-UTF-8 byte in a comment does not crash the probe", func(t *testing.T) {
		dir := t.TempDir()
		body := "# caf\xe9 \xff\n" + krb5Realm("kdc = localhost")
		conf := writeKDCFile(t, dir, "krb5.conf", body)
		res := runKDCProbe(t, map[string]any{"realm": "IPA.PILOT.INTERNAL", "krb5_paths": []string{conf}, "resolvectl": ""})
		if !sameSet(res.KDCNames, []string{"localhost"}) {
			t.Fatalf("kdc_names = %v", res.KDCNames)
		}
	})
}

// TestRegression_KDCPreflightProbeMatchesLiveKinit re-captures every fixture
// row with whatever MIT kinit is on PATH and requires the probe to agree
// with the host kinit actually resolved first. It is skipped when kinit (or
// KRB5_TRACE support) is absent; the committed fixture covers that case.
func TestRegression_KDCPreflightProbeMatchesLiveKinit(t *testing.T) {
	requirePython3ForKDCTests(t)
	if _, err := exec.LookPath("kinit"); err != nil {
		t.Skipf("kinit not on PATH: %v", err)
	}
	fx := loadLibkrb5KDCFixture(t)
	traceFirstHost := func(t *testing.T, raw string) (string, string) {
		t.Helper()
		conf := writeKDCFile(t, t.TempDir(), "krb5.conf", krb5Realm("kdc = "+raw))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kinit", "-c", "MEMORY:probe", "u@IPA.PILOT.INTERNAL")
		cmd.Env = append(os.Environ(), "KRB5_CONFIG="+conf, "KRB5_TRACE=/dev/stdout")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		_ = cmd.Run()
		m := regexp.MustCompile(`Resolving hostname (\S+)`).FindStringSubmatch(out.String())
		if m == nil {
			return "", errb.String()
		}
		return m[1], ""
	}
	if h, _ := traceFirstHost(t, "control.pilot168.invalid:88"); h != "control.pilot168.invalid" {
		t.Skipf("kinit on PATH does not print MIT KRB5_TRACE name resolution (got %q)", h)
	}
	for _, r := range fx.Rows {
		t.Run(r.Name, func(t *testing.T) {
			host, stderr := traceFirstHost(t, r.Raw)
			res := probeKDCConf(t, krb5Realm("kdc = "+r.Raw), nil)
			switch {
			case host == "":
				if len(res.KDCNames) != 0 || len(res.Unparsable) != 1 {
					t.Errorf("kinit resolved nothing for %q (%s); probe: %+v", r.Raw, strings.TrimSpace(stderr), res)
				}
			case isIPText(host):
				if len(res.KDCNames) != 0 {
					t.Errorf("kinit resolved the IP literal %s; probe: %+v", host, res)
				}
			default:
				want := strings.ToLower(strings.TrimRight(host, "."))
				if !sameSet(res.KDCNames, []string{want}) {
					t.Errorf("kinit resolved %q first, probe kdc_names = %v (raw %q)", host, res.KDCNames, r.Raw)
				}
			}
		})
	}
}
