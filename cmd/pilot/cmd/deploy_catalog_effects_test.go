// deploy_catalog_effects_test.go is the cross-layer lint design spec
// docs/tmp/now/spec.md §6.6 requires: deployPlaybook.Reconcile answers
// "is this component eligible for pilot reconcile's day-2 flow?", but
// says nothing about which semantic state domain a reconcile actually
// changes. The outbound webhook feature routes subscriptions by that
// domain (contract.Effects), never by component name (spec §6, INV-7).
// This file locks two things at once so they can never silently drift
// apart: every Reconcile:true deployCatalog entry has a contract with a
// non-empty Effects, AND the exact component/effect-set mapping matches
// design spec §6.4 (internal/spec/outbound_webhook_regression_test.go's
// outboundWebhookEffectMapping, Phase 0) exactly — not just "non-empty".
package cmd

import (
	"reflect"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// wantReconcileEffects is design spec §6.4's exact component -> effects
// table. It must match internal/spec's
// outboundWebhookEffectMapping (Phase 0) key-for-key, value-for-value; if
// deployCatalog grows a new Reconcile:true entry, both tables need a
// deliberate update recording the design decision, not a guess made only
// here to satisfy this test.
var wantReconcileEffects = map[string][]contract.Effect{
	"freeipa-identity": {
		contract.EffectIdentityUsers, contract.EffectIdentityGroups,
		contract.EffectIdentityHostgroups, contract.EffectIdentityNetgroups,
		contract.EffectAccessHBAC, contract.EffectAccessSudo, contract.EffectAccessGrants,
		contract.EffectStorageNFSIdentity,
	},
	"freeipa-dns":               {contract.EffectDNSZones, contract.EffectDNSRecords},
	"freeipa-dns-client":        {contract.EffectNetworkResolver},
	"freeipa-ca-trust":          {contract.EffectTrustCA},
	"freeipa-server-replica":    {contract.EffectIdentityReplica},
	"freeipa-realm-replacement": {contract.EffectIdentityRealm},
	"pilot-gateway-scope":       {contract.EffectIdentityHostgroups, contract.EffectAccessHBAC},
	"internal-endpoint": {
		contract.EffectNetworkEndpoints, contract.EffectDNSRecords,
		contract.EffectTLSCertificates, contract.EffectReverseProxyRoutes,
	},
	"prometheus": {contract.EffectMonitoringScrapeTargets},
}

func sortedEffects(in []contract.Effect) []contract.Effect {
	out := append([]contract.Effect(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestDeployCatalogEffects_E4 (design spec §46.2 E4): every
// deployCatalog entry with Reconcile:true has a contract, and that
// contract's Effects is non-empty.
func TestDeployCatalogEffects_E4(t *testing.T) {
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

	for _, entry := range deployCatalog {
		if !entry.Reconcile {
			continue
		}
		component, ok := catalog.Component(entry.Key)
		if !ok {
			t.Errorf("deployCatalog entry %q (Reconcile:true) has no matching contract", entry.Key)
			continue
		}
		if len(component.Effects) == 0 {
			t.Errorf("contract %q is Reconcile:true but declares no effects (design spec §6.1)", entry.Key)
		}
	}
}

// TestDeployCatalogEffects_E5 (design spec §46.2 E5): freeipa-identity
// declares both identity and access effects — it is the component the
// outbound webhook's primary "roster reconcile" scenario routes on.
func TestDeployCatalogEffects_E5(t *testing.T) {
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
	component, ok := catalog.Component("freeipa-identity")
	if !ok {
		t.Fatal("contract freeipa-identity not found")
	}
	hasIdentity, hasAccess := false, false
	for _, e := range component.Effects {
		if e == contract.EffectIdentityUsers || e == contract.EffectIdentityGroups {
			hasIdentity = true
		}
		if e == contract.EffectAccessHBAC || e == contract.EffectAccessSudo {
			hasAccess = true
		}
	}
	if !hasIdentity || !hasAccess {
		t.Errorf("freeipa-identity effects=%v, want at least one identity.* and one access.* effect", component.Effects)
	}
}

// TestDeployCatalogEffects_E6 (design spec §46.2 E6): freeipa-dns must
// NOT accidentally declare identity/access effects — an
// identity.*/access.*-only subscription must never route a DNS-only
// reconcile.
func TestDeployCatalogEffects_E6(t *testing.T) {
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
	component, ok := catalog.Component("freeipa-dns")
	if !ok {
		t.Fatal("contract freeipa-dns not found")
	}
	for _, e := range component.Effects {
		if e == contract.EffectIdentityUsers || e == contract.EffectIdentityGroups ||
			e == contract.EffectIdentityHostgroups || e == contract.EffectIdentityNetgroups ||
			e == contract.EffectAccessHBAC || e == contract.EffectAccessSudo || e == contract.EffectAccessGrants {
			t.Errorf("freeipa-dns must not declare identity/access effect %q", e)
		}
	}
}

// TestDeployCatalogEffects_E7 (design spec §46.2 E7): the exact mapping
// includes prometheus and pilot-gateway-scope with their exact effect
// sets, and — combined with the count check below — nothing else.
func TestDeployCatalogEffects_E7(t *testing.T) {
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

	reconcileKeys := map[string]bool{}
	for _, entry := range deployCatalog {
		if entry.Reconcile {
			reconcileKeys[entry.Key] = true
		}
	}
	if len(reconcileKeys) != len(wantReconcileEffects) {
		t.Fatalf("deployCatalog has %d Reconcile:true entries, want exactly %d (design spec §6.4) — "+
			"a new reconciler must be added to wantReconcileEffects here AND to "+
			"internal/spec's outboundWebhookEffectMapping with a stated design decision, not guessed",
			len(reconcileKeys), len(wantReconcileEffects))
	}

	for key, wantEffects := range wantReconcileEffects {
		if !reconcileKeys[key] {
			t.Errorf("expected Reconcile:true deployCatalog entry %q not found", key)
			continue
		}
		component, ok := catalog.Component(key)
		if !ok {
			t.Errorf("contract %q not found", key)
			continue
		}
		got := sortedEffects(component.Effects)
		want := sortedEffects(wantEffects)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("contract %q effects = %v, want exactly %v", key, got, want)
		}
	}
}
