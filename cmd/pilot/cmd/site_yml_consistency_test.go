// site_yml_consistency_test.go guards the invariant behind two real,
// separately-discovered incidents (2026-09-14/15, see deploy.go's
// siteYMLImportedPlaybooks doc comment for the full story): a contract's
// site.include/site.tags declarations can silently drift out of sync with
// playbooks/site.yml — the one hand-maintained file that actually decides
// what a site-wide deploy executes — with no error anywhere. The first
// time, that let freeipa-dns/freeipa-identity/internal-endpoint get swept
// into a site-wide deploy's --tags (shared role with an in-scope host)
// despite none of them being import_playbook'd into site.yml. The second
// time, pilot-access-gateway did the same, AND reverse-proxy — a plain
// Site.Include:true component, not even opt-in — was found missing from
// site.yml entirely. Both times the deploy wizard's own output (and, for
// the second, the delivery run's recorded metadata) claimed the component
// was part of a "successful" run while nothing was ever actually applied.
//
// cmd/pilot/cmd/deploy.go's componentsForPlaybook/optInRolesAssignedInScope
// now check playbooks/site.yml's real import list at deploy TIME, so a live
// run can no longer claim success for an unreachable component — but that
// only prevents the SYMPTOM from misleading an operator. This file prevents
// the CAUSE from ever landing unnoticed: it fails at test time, not just
// the next time someone happens to run a live site-wide deploy.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/contract"
)

// TestSiteYMLImportsEveryReachableComponent asserts that every contract
// which claims to run via site-wide deploy — Site.Include:true (runs by
// default), or a non-empty Site.Tags (selectable via --tags during a
// site-wide run, the opt-in-but-swept-in-by-role case) — actually has its
// apply playbook import_playbook'd into playbooks/site.yml. A component
// with neither (Site.Include:false and Site.Tags:[]) is exempt: that is
// the contract's own honest declaration that it is single-component-only,
// exactly like pilot-access-gateway/freeipa-dns/freeipa-identity/
// internal-endpoint/pilot-gateway-scope today.
func TestSiteYMLImportsEveryReachableComponent(t *testing.T) {
	root := repoRootForTest(t)
	t.Setenv("PILOT_ROOT", root)

	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}

	imported, err := siteYMLImportedPlaybooks()
	if err != nil {
		t.Fatal(err)
	}

	for _, component := range catalog.Components() {
		reachable := component.Site.Include || len(component.Site.Tags) > 0
		if !reachable {
			continue
		}
		if !imported[component.Playbooks.Apply] {
			t.Errorf(
				"component %q declares site.include=%v site.tags=%v (expected to run via a "+
					"site-wide deploy) but %q is never `import_playbook`'d into playbooks/site.yml — "+
					"either add the import there, or if this component is genuinely single-component-"+
					"only, set site.include:false and site.tags:[] in its contract to say so honestly "+
					"(see this file's own header comment for the two incidents this exact drift caused)",
				component.ID, component.Site.Include, component.Site.Tags, component.Playbooks.Apply)
		}
	}
}

// siteYMLImport is one `import_playbook` entry of playbooks/site.yml, in
// file order. Playbook uses the "playbooks/apply/<x>.yml" form that
// contract.Playbooks.Apply uses.
type siteYMLImport struct {
	Playbook string
	Tags     []string
}

// readSiteYMLImports parses playbooks/site.yml under root into its ordered
// import list. siteYMLImportedPlaybooks only returns a set; the ordering
// and tag guards below need the order and each import's own tags.
func readSiteYMLImports(t *testing.T, root string) []siteYMLImport {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "playbooks", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		ImportPlaybook string   `yaml:"import_playbook"`
		Tags           []string `yaml:"tags"`
	}
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse playbooks/site.yml: %v", err)
	}
	var imports []siteYMLImport
	for _, entry := range entries {
		if entry.ImportPlaybook == "" {
			continue
		}
		imports = append(imports, siteYMLImport{Playbook: "playbooks/" + entry.ImportPlaybook, Tags: entry.Tags})
	}
	return imports
}

// siteYMLStandaloneComponents lists the contracts whose role is a real
// inventory role (not the "all" pseudo-role) and whose apply playbook is
// deliberately NOT imported by playbooks/site.yml, each with the reason
// from the four-point criterion in AGENTS.md section 4.3 (issue #362):
//
//  1. expressed by a host role: the inventory says "this host looks like
//     this";
//  2. repeatable: the second apply is changed=0, so every deploy may run it;
//  3. the first apply can run automatically, and an unmet precondition
//     fails clearly instead of hanging or reporting success;
//  4. needs no extra one-time authorization.
//
// A component meeting all four is imported (freeipa-server-replica and
// freeipa-dns-client are, since #362); anything else stays standalone and is
// listed here. The list is a ratchet: an entry whose component has since
// been imported (or removed, or switched to role "all") fails the test, so
// it cannot rot into an unexplained exemption.
var siteYMLStandaloneComponents = map[string]string{
	"agent-controller":           "criterion 2: its always-tagged backup Steps 3-5 report changed on every run, so a site-wide second apply would never be changed=0 (#195); experimental Phase 1. Import it once #195 is fixed",
	"freeipa-dns":                "criterion 1: a manifest-driven day-2 reconciler, not a host role; its role (freeipa-server) is shared with freeipa-server, so importing it would sweep it into every deploy that has a FreeIPA server host (the 2026-09-14 incident)",
	"freeipa-identity":           "criterion 1/4: roster-driven, not a host role, affects every user, has its own lock and execution engine; role (freeipa-server) is shared with the server contract",
	"freeipa-realm-replacement":  "criterion 2/3/4: one-time irreversible migration; a prior-state file makes it refuse a second run",
	"internal-endpoint":          "criterion 1: manifest-driven fleet-wide DNS baseline reconciler, not a host role; role (freeipa-server) is shared with the server contract",
	"pilot-access-target-policy": "criterion 4: tightening a transport target's sshd is a deliberate operator action (docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md section 13), exclusive with the gateway/directory roles",
	"pilot-gateway-scope":        "criterion 1/4: the backend of the `pilot gateway-scope` CLI; publishes a scope hostgroup on operator request, not a per-host role",
}

// siteYMLImportTagIDAllowlist is the one existing import that predates the
// rule "an import's tags include the component ID". effectiveDeployment-
// TagScopes hands component IDs to ansible as --tags when --limit pulls a
// provider host in by dependency, so an import without its ID cannot be
// selected that way. os-patch-sla is nobody's dependency, so nothing
// selects it by ID today; its contract site.tags ([maintenance,
// os-patch-sla]) vs the import's tags ([patch]) is a separate drift
// tracked as a follow-up to #362. The entry is a ratchet like the one above.
var siteYMLImportTagIDAllowlist = map[string]string{
	"os-patch-sla": "import tags are [patch]; no component depends on os-patch-sla, so --limit dependency expansion never needs its ID; separate site.tags drift, follow-up to #362",
}

// siteYMLOrderRule says that component Before must run earlier in site.yml
// than component After, and why.
type siteYMLOrderRule struct {
	Before, After string
	Why           string
}

// siteYMLOrderRules are the placement constraints of the two host roles
// issue #362 imports. Consumers of freeipa-dns-client are added by
// siteYMLOrderRulesFor from the deploy catalog, not listed by hand.
var siteYMLOrderRules = []siteYMLOrderRule{
	{"freeipa-server", "freeipa-server-replica", "the primary must exist before a replica joins it"},
	{"freeipa-server-replica", "dns", "dns-apply.yml asks FreeIPA which replicas serve DNS: an unpromoted replica is left out on the first apply and added on the second, so the second apply is not changed=0, and its G5 gate fails on a not-yet-promoted replica with freeipa_setup_dns: true"},
	{"freeipa-server-replica", "freeipa-client", "the client pool and resolver tasks read the same replica-aware provider list"},
	{"dns", "freeipa-dns-client", "freeipa-dns-client asks every nameserver it is about to write, so the dns tier must already answer"},
	{"freeipa-client", "freeipa-dns-client", "freeipa-dns-client sits after enrolment so every later consumer finds the hosts of its group already resolving FreeIPA names"},
}

// siteYMLDNSClientConsumers are consumers of freeipa-dns-client beyond the
// deploy catalog's autoHostVar playbooks: components whose playbooks reach a
// FreeIPA server by FQDN on the same hosts.
var siteYMLDNSClientConsumers = []string{"pilot-session-store", "freeipa-nfs-server", "freeipa-nfs-client"}

// siteYMLOrderRulesFor returns siteYMLOrderRules plus "freeipa-dns-client
// before X" for every cross-role consumer: a deploy catalog entry with
// autoHostVars (deploy.go's fqdnForGroupHost hands such a consumer a FreeIPA
// FQDN as soon as its whole group is in freeipa-dns-client) and
// siteYMLDNSClientConsumers.
func siteYMLOrderRulesFor(catalog contract.Catalog) []siteYMLOrderRule {
	rules := append([]siteYMLOrderRule(nil), siteYMLOrderRules...)
	byApply := map[string]string{}
	for _, component := range catalog.Components() {
		byApply[component.Playbooks.Apply] = component.ID
	}
	consumers := map[string]bool{}
	for _, entry := range deployCatalog {
		if len(entry.AutoHostVars) == 0 {
			continue
		}
		if id, ok := byApply[entry.Playbook]; ok {
			consumers[id] = true
		}
	}
	for _, id := range siteYMLDNSClientConsumers {
		consumers[id] = true
	}
	ids := make([]string, 0, len(consumers))
	for id := range consumers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rules = append(rules, siteYMLOrderRule{"freeipa-dns-client", id,
			"fqdnForGroupHost gives " + id + "'s group FreeIPA FQDNs once its hosts are in freeipa-dns-client; they must resolve on the first apply"})
	}
	return rules
}

// siteYMLHostRoleProblems returns every violation of the site.yml
// invariants of issue #362 for the given catalog, import list and
// allowlists. It is the pure core of TestSiteYMLHostRolesAreImportedOrStandalone
// so the mutation tests can feed it a broken site.yml.
//
//   - every component whose role is not the "all" pseudo-role has its apply
//     playbook imported, or is in standalone with a reason;
//   - a stale standalone entry (imported now, unknown, or role "all") fails;
//   - every imported component's import tags include its own ID, unless it
//     is in tagIDAllowlist; a stale tagIDAllowlist entry fails;
//   - the ordering rules hold for every rule whose both sides are imported.
func siteYMLHostRoleProblems(catalog contract.Catalog, imports []siteYMLImport, standalone, tagIDAllowlist map[string]string, rules []siteYMLOrderRule) []string {
	var problems []string
	position := map[string]int{}
	tagsOf := map[string][]string{}
	for i, imp := range imports {
		if _, seen := position[imp.Playbook]; !seen {
			position[imp.Playbook] = i
			tagsOf[imp.Playbook] = imp.Tags
		}
	}
	components := catalog.Components()
	byID := map[string]contract.Contract{}
	for _, component := range components {
		byID[component.ID] = component
	}

	for _, component := range components {
		_, imported := position[component.Playbooks.Apply]
		reason, allowed := standalone[component.ID]
		switch {
		case component.Role == "all":
			// A pseudo-role has no host to assign, so it is never a
			// host role (freeipa-ca-trust); see
			// TestComponentsForPlaybook_SiteWideOptInExcludesAllPseudoRole.
		case !imported && !allowed:
			problems = append(problems, fmt.Sprintf(
				"component %q (role %q) is a host role but %s is not imported by playbooks/site.yml, so a site-wide deploy silently skips it for every host the inventory assigns it to. "+
					"Import it, or list it in siteYMLStandaloneComponents with the reason from the four-point criterion in AGENTS.md section 4.3",
				component.ID, component.Role, component.Playbooks.Apply))
		case imported && allowed:
			problems = append(problems, fmt.Sprintf(
				"siteYMLStandaloneComponents lists %q (%s) but playbooks/site.yml imports it now: delete the stale entry", component.ID, reason))
		}
	}
	for id := range standalone {
		component, ok := byID[id]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("siteYMLStandaloneComponents lists %q, which is not a contract: delete the stale entry", id))
		case component.Role == "all":
			problems = append(problems, fmt.Sprintf("siteYMLStandaloneComponents lists %q, whose role is the \"all\" pseudo-role the rule never checks: delete the entry", id))
		}
	}

	for _, component := range components {
		tags, imported := tagsOf[component.Playbooks.Apply]
		if !imported {
			continue
		}
		hasID := slices.Contains(tags, component.ID)
		_, allowed := tagIDAllowlist[component.ID]
		switch {
		case !hasID && !allowed:
			problems = append(problems, fmt.Sprintf(
				"playbooks/site.yml imports %s with tags %v, which do not include the component ID %q: a limited deploy that pulls %q in as a dependency passes its ID to ansible as --tags and would select nothing",
				component.Playbooks.Apply, tags, component.ID, component.ID))
		case hasID && allowed:
			problems = append(problems, fmt.Sprintf("siteYMLImportTagIDAllowlist lists %q but its import tags include the ID now: delete the stale entry", component.ID))
		}
	}
	for id := range tagIDAllowlist {
		if component, ok := byID[id]; !ok {
			problems = append(problems, fmt.Sprintf("siteYMLImportTagIDAllowlist lists %q, which is not a contract: delete the stale entry", id))
		} else if _, imported := position[component.Playbooks.Apply]; !imported {
			problems = append(problems, fmt.Sprintf("siteYMLImportTagIDAllowlist lists %q, which site.yml does not import: delete the stale entry", id))
		}
	}

	for _, rule := range rules {
		before, okBefore := byID[rule.Before]
		after, okAfter := byID[rule.After]
		if !okBefore || !okAfter {
			problems = append(problems, fmt.Sprintf("order rule %s -> %s names an unknown contract", rule.Before, rule.After))
			continue
		}
		posBefore, importedBefore := position[before.Playbooks.Apply]
		posAfter, importedAfter := position[after.Playbooks.Apply]
		if !importedBefore || !importedAfter {
			// A consumer that site.yml does not import has no position to
			// check; the import rule above reports an unimported host role.
			continue
		}
		if posBefore >= posAfter {
			problems = append(problems, fmt.Sprintf(
				"playbooks/site.yml runs %s (import #%d) before %s (import #%d), but %s must run first: %s",
				after.ID, posAfter, before.ID, posBefore, before.ID, rule.Why))
		}
	}
	return problems
}

func loadRealCatalogForSiteTests(t *testing.T) (string, contract.Catalog) {
	t.Helper()
	root := repoRootForTest(t)
	t.Setenv("PILOT_ROOT", root)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return root, catalog
}

// TestSiteYMLHostRolesAreImportedOrStandalone is the repository-wide guard
// for issue #362. A contract whose role is a real inventory role, and whose
// apply playbook playbooks/site.yml does not import, is dropped silently by
// a site-wide deploy (optInRolesAssignedInScope, componentsForPlaybook;
// 9550b38a) while the run exits 0: a rebuilt replica host had no FreeIPA and
// the deploy still reported success. Every such component must therefore be
// imported or carry a reasoned entry in siteYMLStandaloneComponents; every
// import must carry its component ID as a tag (the ID is what
// effectiveDeploymentTagScopes passes to ansible for dependency-expanded
// --limit runs); and the imports of the two host roles added for #362 must
// keep their order (siteYMLOrderRules). A new component's PR has to
// justify "in" or "out" against the four points in AGENTS.md section 4.3.
func TestSiteYMLHostRolesAreImportedOrStandalone(t *testing.T) {
	root, catalog := loadRealCatalogForSiteTests(t)
	imports := readSiteYMLImports(t, root)
	rules := siteYMLOrderRulesFor(catalog)

	if problems := siteYMLHostRoleProblems(catalog, imports, siteYMLStandaloneComponents, siteYMLImportTagIDAllowlist, rules); len(problems) > 0 {
		t.Fatalf("playbooks/site.yml and the contract catalog disagree (issue #362):\n  - %s", strings.Join(problems, "\n  - "))
	}

	// The two components #362 imports must be the ones this guard sees as
	// imported; if the rule lists were emptied the checks above would pass
	// vacuously.
	for _, id := range []string{"freeipa-server-replica", "freeipa-dns-client"} {
		component, ok := catalog.Component(id)
		if !ok {
			t.Fatalf("contract %q missing", id)
		}
		found := false
		for _, imp := range imports {
			if imp.Playbook == component.Playbooks.Apply {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not imported by playbooks/site.yml", id)
		}
		if _, listed := siteYMLStandaloneComponents[id]; listed {
			t.Errorf("%s must not be listed as standalone", id)
		}
	}
	if len(rules) <= len(siteYMLOrderRules) {
		t.Errorf("no freeipa-dns-client consumer found from the deploy catalog (%d rules): the order guard would pass vacuously", len(rules))
	}
}

// TestSiteYMLHostRoleGuardFailsOnTheBrokenShapes proves the guard above is
// not vacuous (AGENTS.md section 5.12): it feeds the pure checker the real
// site.yml with one deliberate defect at a time and requires the problem the
// guard exists for, naming the right component.
func TestSiteYMLHostRoleGuardFailsOnTheBrokenShapes(t *testing.T) {
	root, catalog := loadRealCatalogForSiteTests(t)
	real := readSiteYMLImports(t, root)
	rules := siteYMLOrderRulesFor(catalog)
	apply := func(id string) string {
		component, ok := catalog.Component(id)
		if !ok {
			t.Fatalf("contract %q missing", id)
		}
		return component.Playbooks.Apply
	}
	without := func(playbook string) []siteYMLImport {
		var out []siteYMLImport
		for _, imp := range real {
			if imp.Playbook != playbook {
				out = append(out, imp)
			}
		}
		return out
	}
	moveToEnd := func(playbook string) []siteYMLImport {
		out := without(playbook)
		for _, imp := range real {
			if imp.Playbook == playbook {
				out = append(out, imp)
			}
		}
		return out
	}
	retag := func(playbook string, tags []string) []siteYMLImport {
		out := append([]siteYMLImport(nil), real...)
		for i := range out {
			if out[i].Playbook == playbook {
				out[i].Tags = tags
			}
		}
		return out
	}

	cases := []struct {
		name       string
		imports    []siteYMLImport
		standalone map[string]string
		tagAllow   map[string]string
		want       string
	}{
		{name: "replica import removed (the #362 defect)", imports: without(apply("freeipa-server-replica")), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: `component "freeipa-server-replica"`},
		{name: "dns-client import removed (the #362 defect)", imports: without(apply("freeipa-dns-client")), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: `component "freeipa-dns-client"`},
		{name: "dns-client moved to the end of site.yml", imports: moveToEnd(apply("freeipa-dns-client")), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: "freeipa-nfs-server"},
		{name: "replica moved after dns", imports: moveToEnd(apply("freeipa-server-replica")), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: "freeipa-server-replica (import #"},
		{name: "dns-client import tags lose the component ID", imports: retag(apply("freeipa-dns-client"), []string{"freeipa"}), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: `component ID "freeipa-dns-client"`},
		{name: "replica import tags lose the component ID", imports: retag(apply("freeipa-server-replica"), []string{"freeipa"}), standalone: siteYMLStandaloneComponents, tagAllow: siteYMLImportTagIDAllowlist,
			want: `component ID "freeipa-server-replica"`},
		{name: "stale standalone entry for an imported component", imports: real,
			standalone: map[string]string{"freeipa-dns-client": "stale"}, tagAllow: siteYMLImportTagIDAllowlist,
			want: `lists "freeipa-dns-client"`},
		{name: "stale tag allowlist entry", imports: real, standalone: siteYMLStandaloneComponents,
			tagAllow: map[string]string{"freeipa-dns-client": "stale", "os-patch-sla": "x"},
			want:     `siteYMLImportTagIDAllowlist lists "freeipa-dns-client"`},
		{name: "standalone entry removed for a component that is not imported", imports: real,
			standalone: map[string]string{"freeipa-identity": "kept"}, tagAllow: siteYMLImportTagIDAllowlist,
			want: `component "agent-controller"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := siteYMLHostRoleProblems(catalog, tc.imports, tc.standalone, tc.tagAllow, rules)
			joined := strings.Join(problems, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, joined)
			}
		})
	}

	t.Run("the real site.yml has no problem", func(t *testing.T) {
		if problems := siteYMLHostRoleProblems(catalog, real, siteYMLStandaloneComponents, siteYMLImportTagIDAllowlist, rules); len(problems) > 0 {
			t.Fatalf("unexpected problems: %v", problems)
		}
	})
}
