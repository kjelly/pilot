package spec

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Every consumer that verifies the WHOLE docs/verification/freeipa-client.md
// must create the fixture accounts the spec probes before it verifies:
//
//   - fixtures/freeipa-client-fixtures.yml           C5/C8   pilotuser + the pilot-all sudo rule
//   - fixtures/freeipa-client-pwexpiry-fixtures.yml  C15-C17 pilot-pwexpired/-pwvalid/-nopw
//
// Both run on the FreeIPA server. A consumer that skips one gets extra FAIL rows
// and `topology test` rolls the chain back (the per-host recording chain did this
// for C15-C17 after those rows were added). This is a consumer-consistency check
// (AGENTS.md section 5.7): the consumers are discovered, not listed, so a new
// script that verifies the spec without the fixtures fails here.

const (
	fcClientFixtures  = "playbooks/test/fixtures/freeipa-client-fixtures.yml"
	fcPwexpiryFixture = "playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml"
	fcClientApply     = "playbooks/apply/freeipa-client-apply.yml"
)

// fcConsumerAllowlist lists the consumers that verify the whole spec on purpose
// without creating the fixtures. The key is the repo-relative source. The entry
// is a ratchet: it must still verify the spec, still run the listed playbook,
// and that playbook must still not import the pwexpiry fixtures; a consumer that
// gained them must be removed from this list.
var fcConsumerAllowlist = map[string]struct{ playbook, reason string }{
	"scripts/topology-checkmode-test.sh": {
		playbook: "playbooks/site.yml",
		reason:   "site.yml on the minimal-poc topology: the fixture-bound rows (C5/C8/C15-C17) do not pass there, documented in docs/runbooks/minimal-poc-architecture.md",
	},
	"docs/topologies/minimal-poc-topology.yaml": {
		playbook: "playbooks/site.yml",
		reason:   "the site-wide verification set of the same minimal-poc topology (no chain playbook of its own); same documented limit",
	},
}

type fcConsumer struct {
	source   string // repo-relative path of the script or topology that verifies the spec
	playbook string // repo-relative playbook it runs ("" when the source names none)
}

type fcImport struct {
	path string
	vars map[string]any
}

var (
	fcVerifyRE      = regexp.MustCompile(`--verify\s+["']?docs/verification/freeipa-client\.md`)
	fcScriptPBRE    = regexp.MustCompile(`(?m)^PLAYBOOK="(?:\$\{PLAYBOOK:-)?([^"}]+)\}?"`)
	fcFlagPlaybook  = regexp.MustCompile(`--playbook\s+["']?(playbooks/[^\s"'\\]+)`)
	fcRepoRoot      = "../.."
	fcLeafDirPrefix = []string{"playbooks/test/fixtures/", "playbooks/apply/"}
)

func fcRead(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fcRepoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

// fcDiscoverConsumers finds every script and topology header that verifies the
// whole freeipa-client spec.
func fcDiscoverConsumers(t *testing.T) []fcConsumer {
	t.Helper()
	var out []fcConsumer
	scripts, err := filepath.Glob(filepath.Join(fcRepoRoot, "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range scripts {
		rel := filepath.ToSlash(strings.TrimPrefix(s, fcRepoRoot+string(filepath.Separator)))
		src := fcRead(t, rel)
		if !fcVerifyRE.MatchString(src) {
			continue
		}
		pb := ""
		if m := fcScriptPBRE.FindStringSubmatch(src); m != nil {
			pb = m[1]
		} else if m := fcFlagPlaybook.FindStringSubmatch(src); m != nil {
			pb = m[1]
		}
		if pb == "" {
			t.Errorf("%s verifies docs/verification/freeipa-client.md but the playbook it runs cannot be resolved (expected a PLAYBOOK= assignment or a --playbook flag)", rel)
		}
		out = append(out, fcConsumer{source: rel, playbook: pb})
	}
	topologies, err := filepath.Glob(filepath.Join(fcRepoRoot, "docs", "topologies", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range topologies {
		rel := filepath.ToSlash(strings.TrimPrefix(f, fcRepoRoot+string(filepath.Separator)))
		src := fcRead(t, rel)
		if !fcVerifyRE.MatchString(src) {
			continue
		}
		pb := ""
		if m := fcFlagPlaybook.FindStringSubmatch(src); m != nil {
			pb = m[1]
		}
		out = append(out, fcConsumer{source: rel, playbook: pb})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].source < out[j].source })
	return out
}

// fcFlatten returns the playbooks a chain runs, in order, following
// import_playbook through chain files. Fixture and apply playbooks are leaves
// (the pwexpiry fixtures themselves import freeipa-client-fixtures.yml for other
// accounts, which must not count as the C5/C8 fixture).
func fcFlatten(t *testing.T, rel string, depth int) []fcImport {
	t.Helper()
	if depth > 8 {
		t.Fatalf("import_playbook nesting too deep at %s", rel)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(fcRead(t, rel)), &plays); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	var out []fcImport
	for _, p := range plays {
		ref, _ := p["ansible.builtin.import_playbook"].(string)
		if ref == "" {
			ref, _ = p["import_playbook"].(string)
		}
		if ref == "" {
			continue
		}
		target := path.Clean(path.Join(path.Dir(rel), ref))
		vars, _ := p["vars"].(map[string]any)
		leaf := false
		for _, prefix := range fcLeafDirPrefix {
			if strings.HasPrefix(target, prefix) {
				leaf = true
			}
		}
		if leaf {
			out = append(out, fcImport{path: target, vars: vars})
			continue
		}
		out = append(out, fcFlatten(t, target, depth+1)...)
	}
	return out
}

// fcFixtureViolations is the rule itself, over the ordered playbooks a chain runs.
func fcFixtureViolations(chain []fcImport) []string {
	var v []string
	idx := func(p string, accept func(map[string]any) bool) int {
		for i, e := range chain {
			if e.path == p && (accept == nil || accept(e.vars)) {
				return i
			}
		}
		return -1
	}
	// C5/C8 need the default pilotuser: an import that overrides ipa_fixture_user
	// creates some other account.
	defaultUser := func(vars map[string]any) bool { _, set := vars["ipa_fixture_user"]; return !set }
	client := idx(fcClientFixtures, defaultUser)
	pwexpiry := idx(fcPwexpiryFixture, nil)
	apply := idx(fcClientApply, nil)
	if client < 0 {
		v = append(v, "does not import "+fcClientFixtures+" for the default pilotuser (C5/C8)")
	}
	if pwexpiry < 0 {
		v = append(v, "does not import "+fcPwexpiryFixture+" (C15-C17 probe pilot-pwexpired/-pwvalid/-nopw)")
	}
	if apply < 0 {
		v = append(v, "does not import "+fcClientApply)
	}
	if apply >= 0 && client > apply {
		v = append(v, "imports "+fcClientFixtures+" after the client apply (the client's SSSD must see the account on its first lookup)")
	}
	if apply >= 0 && pwexpiry > apply {
		v = append(v, "imports "+fcPwexpiryFixture+" after the client apply (the client's SSSD must see the accounts on its first lookup)")
	}
	return v
}

func fcHasImport(chain []fcImport, p string) bool {
	for _, e := range chain {
		if e.path == p {
			return true
		}
	}
	return false
}

func TestRegression_FreeipaClientFullSpecConsumersCreateTheirFixtures(t *testing.T) {
	consumers := fcDiscoverConsumers(t)

	// The discovery must actually find the known consumers; an empty result would
	// make every check below pass without checking anything (AGENTS.md 5.12).
	found := map[string]string{}
	for _, c := range consumers {
		found[c.source] = c.playbook
	}
	for source, wantPlaybook := range map[string]string{
		"scripts/per-host-recording-topology-test.sh":              "playbooks/test/per-host-recording-topology.yml",
		"scripts/topology-checkmode-test.sh":                       "playbooks/site.yml",
		"docs/topologies/freeipa-client-pwexpiry-topology.yaml":    "playbooks/test/freeipa-client-pwexpiry-chain.yml",
		"docs/topologies/freeipa-client-pwexpiry-ha-topology.yaml": "playbooks/test/freeipa-client-pwexpiry-ha-chain.yml",
	} {
		got, ok := found[source]
		if !ok {
			t.Errorf("discovery did not find %s as a consumer of the whole freeipa-client spec", source)
		} else if got != wantPlaybook {
			t.Errorf("%s resolves to playbook %q, want %q", source, got, wantPlaybook)
		}
	}

	for _, c := range consumers {
		if entry, listed := fcConsumerAllowlist[c.source]; listed {
			if c.playbook != "" && c.playbook != entry.playbook {
				t.Errorf("%s is allowlisted for %s but now runs %s: review the entry (%s)", c.source, entry.playbook, c.playbook, entry.reason)
			}
			continue
		}
		if c.playbook == "" {
			t.Errorf("%s verifies the whole freeipa-client spec but names no --playbook: add the chain to its header, or list it in fcConsumerAllowlist with the reason", c.source)
			continue
		}
		for _, msg := range fcFixtureViolations(fcFlatten(t, c.playbook, 0)) {
			t.Errorf("%s verifies the whole freeipa-client spec with %s, which %s: C5/C8/C15-C17 FAIL and the chain rolls back (spec section 2, 7.2)", c.source, c.playbook, msg)
		}
	}

	// Ratchet: an allowlisted consumer must still exist, still verify the spec, and
	// still lack the fixtures. One that gained them leaves the list.
	for source, entry := range fcConsumerAllowlist {
		if _, ok := found[source]; !ok {
			t.Errorf("fcConsumerAllowlist lists %s, which no longer verifies the whole freeipa-client spec: remove the entry", source)
			continue
		}
		if fcHasImport(fcFlatten(t, entry.playbook, 0), fcPwexpiryFixture) {
			t.Errorf("%s (allowlisted: %s) now imports %s through %s: remove it from fcConsumerAllowlist", source, entry.reason, fcPwexpiryFixture, entry.playbook)
		}
	}
}

// The rule must be able to fail: synthetic chains with each defect (AGENTS.md
// 5.12 wants a triggering case as well as a passing one).
func TestRegression_FreeipaClientFixtureRuleTriggers(t *testing.T) {
	imp := func(p string) fcImport { return fcImport{path: p} }
	good := []fcImport{imp("playbooks/apply/freeipa-server-apply.yml"), imp(fcClientFixtures), imp(fcPwexpiryFixture), imp(fcClientApply)}
	if v := fcFixtureViolations(good); len(v) != 0 {
		t.Fatalf("a complete chain must pass, got %v", v)
	}
	cases := []struct {
		name  string
		chain []fcImport
		want  string
	}{
		{"missing pwexpiry fixtures", []fcImport{imp(fcClientFixtures), imp(fcClientApply)}, fcPwexpiryFixture},
		{"missing client fixtures", []fcImport{imp(fcPwexpiryFixture), imp(fcClientApply)}, fcClientFixtures},
		{"pwexpiry fixtures after the client", []fcImport{imp(fcClientFixtures), imp(fcClientApply), imp(fcPwexpiryFixture)}, "after the client apply"},
		{"client fixtures for another user", []fcImport{{path: fcClientFixtures, vars: map[string]any{"ipa_fixture_user": "someone"}}, imp(fcPwexpiryFixture), imp(fcClientApply)}, "default pilotuser"},
		{"no client apply", []fcImport{imp(fcClientFixtures), imp(fcPwexpiryFixture)}, fcClientApply},
	}
	for _, tc := range cases {
		v := strings.Join(fcFixtureViolations(tc.chain), "\n")
		if !strings.Contains(v, tc.want) {
			t.Errorf("%s: violations %q must mention %q", tc.name, v, tc.want)
		}
	}
}
