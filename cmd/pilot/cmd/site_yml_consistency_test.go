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
	"testing"

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
