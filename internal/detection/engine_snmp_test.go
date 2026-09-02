package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// networkDeviceProfilePath is the real Phase 5 SNMP feature profile file —
// these tests load it exactly as pilot-detection-engine would in
// production (spec §9.10), not a hand-typed copy that could silently
// drift from what actually ships.
const networkDeviceProfilePath = "../../monitoring/detection/feature-profiles/network-device-ifmib-v1.yaml"

func loadNetworkDeviceProfile(t *testing.T) FeatureProfile {
	t.Helper()
	profile, err := LoadFeatureProfile(networkDeviceProfilePath)
	if err != nil {
		t.Fatalf("LoadFeatureProfile(%s): %v", networkDeviceProfilePath, err)
	}
	return profile
}

// snmpVectorResponse renders one Prometheus-compatible instant-query
// response with the real label shape Phase 2's compiler actually attaches
// to a scraped SNMP series (internal/monitoring/compile.go): pilot_target,
// site, pilot_protocol, detection_cohort — the same label set spec
// §9.10's PromQL filters/groups by, so these fixtures are not divorced
// from what a real Thanos chain returns (see
// docs/runbooks/snmp-monitoring-registry.md for the real disposable-VM
// proof the labels are compiled exactly this way).
func snmpVectorResponse(at int64, target, site, cohort, value string) string {
	return fmt.Sprintf(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_target":%q,"site":%q,"pilot_protocol":"snmp","detection_cohort":%q},"value":[%d,%q]}]}}`,
		target, site, cohort, at, value)
}

// TestEngine_SNMPProfile_FixtureAnomalyProducesSignalEvent is
// docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md
// §15 Phase 5 exit gate's "fixture anomaly produces SignalEvent" +
// "SignalEvent subject labels correct": drives the REAL
// network-device-ifmib-v1.yaml profile through a robust-baseline-v1
// warm-up (mirroring TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog's
// established pattern) using fixture Thanos responses shaped like a real
// SNMP-scraped series, then a genuine error-rate spike, and asserts the
// resulting episode/alert carry subject_kind=network_device and never
// pilot_host.
func TestEngine_SNMPProfile_FixtureAnomalyProducesSignalEvent(t *testing.T) {
	profile := loadNetworkDeviceProfile(t)

	value := "1.0" // interface_error_rate/interface_discard_rate baseline
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := r.URL.Query().Get("time")
		var atInt int64
		fmt.Sscanf(at, "%d", &atInt)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, snmpVectorResponse(atInt, "core-sw-01", "site-a", "edge-switches", value))
	}))
	defer server.Close()

	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	base := time.Now().Unix()
	for i := 0; i < minReadyBuckets; i++ {
		if _, err := engine.RunCycle(context.Background(), base+int64(i)*60); err != nil {
			t.Fatalf("RunCycle warm-up cycle %d: %v", i, err)
		}
	}

	// Spike: a real interface error/discard storm. Two consecutive
	// critical-threshold cycles are required to fire (spec §20.2:
	// checkFiringTrigger's CriticalStreak>=2 rule), mirroring the
	// existing TestLifecycle_* tests' own two-call pattern.
	value = "500.0"
	var outcomes []HostCycleOutcome
	for i := 0; i < 2; i++ {
		var err error
		outcomes, err = engine.RunCycle(context.Background(), base+int64(minReadyBuckets+i)*60)
		if err != nil {
			t.Fatalf("RunCycle spike cycle %d: %v", i, err)
		}
		if len(outcomes) != 1 || !outcomes[0].LocalScore.Valid || outcomes[0].LocalScore.Score < CriticalThreshold {
			t.Fatalf("spike cycle %d outcome = %+v, want a Valid, critical-threshold local score", i, outcomes)
		}
	}

	active, err := store.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("expected exactly one active episode after the spike, got %d: %+v", len(active), active)
	}
	ep := active[0]
	if ep.SubjectID != "core-sw-01" {
		t.Errorf("SubjectID = %q, want core-sw-01", ep.SubjectID)
	}
	if ep.SubjectKind != "network_device" {
		t.Errorf("SubjectKind = %q, want network_device", ep.SubjectKind)
	}
	if ep.PilotHost != "" {
		t.Errorf("PilotHost = %q, want empty string for a non-managed-host subject", ep.PilotHost)
	}
	if ep.Site != "site-a" {
		t.Errorf("Site = %q, want site-a", ep.Site)
	}
}

// TestEngine_SNMPProfile_NegativeLanes drives the real
// network-device-ifmib-v1.yaml profile through spec §15 Phase 5's
// required negative lanes — normal/stale/missing/ambiguous — each via the
// exact same ClassifySample/GroupSamplesByKey path RunCycle itself uses,
// with the profile's OWN sampling window (90s/5s, not the managed-host
// default 45s/5s).
func TestEngine_SNMPProfile_NegativeLanes(t *testing.T) {
	profile := loadNetworkDeviceProfile(t)
	identity := profile.EffectiveIdentity()
	maxAge := profile.MaxSampleAge()
	skew := profile.FutureSkewTolerance()
	if maxAge != 90*time.Second || skew != 5*time.Second {
		t.Fatalf("profile sampling = (%v, %v), want (90s, 5s) per spec §9.10", maxAge, skew)
	}
	feature, ok := profile.Feature("interface_error_rate")
	if !ok {
		t.Fatal("network-device-ifmib-v1 must declare interface_error_rate")
	}
	const evalTime = int64(1_000_000)

	t.Run("normal", func(t *testing.T) {
		_, validity := ClassifySample([]RawSample{{Timestamp: evalTime - 30, Value: 5.0}}, evalTime, feature, maxAge, skew)
		if validity != ValidityValid {
			t.Fatalf("validity = %q, want valid", validity)
		}
	})
	t.Run("stale", func(t *testing.T) {
		// 90s profile window: 91s old must be stale, unlike the
		// managed-host default (45s) which would already call this stale
		// at 46s — proving the profile's own sampling override is what's
		// actually in effect, not the global default.
		_, validity := ClassifySample([]RawSample{{Timestamp: evalTime - 91, Value: 5.0}}, evalTime, feature, maxAge, skew)
		if validity != ValidityStale {
			t.Fatalf("validity = %q, want stale (91s > 90s profile maxSampleAge)", validity)
		}
		_, validity = ClassifySample([]RawSample{{Timestamp: evalTime - 60, Value: 5.0}}, evalTime, feature, maxAge, skew)
		if validity != ValidityValid {
			t.Fatalf("60s old validity = %q, want valid (well within the 90s profile window)", validity)
		}
	})
	t.Run("missing", func(t *testing.T) {
		_, validity := ClassifySample(nil, evalTime, feature, maxAge, skew)
		if validity != ValidityMissing {
			t.Fatalf("validity = %q, want missing", validity)
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		metrics := []map[string]string{
			{"pilot_target": "core-sw-01", "site": "site-a"},
			{"pilot_target": "core-sw-01", "site": "site-a"}, // unaggregated duplicate series
		}
		samples := []RawSample{{Timestamp: evalTime, Value: 5.0}, {Timestamp: evalTime, Value: 6.0}}
		grouped, _ := GroupSamplesByKey(metrics, samples, identity)
		key := SeriesKey{PilotHost: "core-sw-01", Site: "site-a"}
		raw, ok := grouped[key]
		if !ok || len(raw) != 2 {
			t.Fatalf("expected both duplicate series bucketed under one key, got %+v", grouped)
		}
		_, validity := ClassifySample(raw, evalTime, feature, maxAge, skew)
		if validity != ValidityAmbiguousSeries {
			t.Fatalf("validity = %q, want ambiguous_series for >1 sample under one subject key", validity)
		}
	})
}

// TestEngine_SNMPProfile_AlertPayloadCorrelatesWithAgentControllerContract
// is the Phase 5 exit gate's "agent correlation": internal/agentcontroller
// cannot be imported here (agentcontroller -> repair -> diagnose is the
// one-directional layering internal/diagnose's package doc already
// documents; a reverse import from internal/detection would add nothing
// and risks a cycle later), so this test instead asserts the exact label
// shape internal/agentcontroller.normalizeSubject's documented precedence
// (spec §10.1: pilot_subject > pilot_host > pilot_target > none) resolves
// this profile's real alert payload to the correct IncidentSubject. Since
// buildAlertPayload (Phase 4) always sets pilot_subject/pilot_subject_kind
// for EVERY Detection Engine alert, the real normalizeSubject code path
// that fires here is its FIRST case (labels["pilot_subject"] != ""),
// where Managed = (pilot_subject_kind == "managed_host") — mirrored here
// verbatim from internal/agentcontroller/normalize.go's normalizeSubject
// to catch drift between the two packages' contracts.
func TestEngine_SNMPProfile_AlertPayloadCorrelatesWithAgentControllerContract(t *testing.T) {
	profile := loadNetworkDeviceProfile(t)
	kind := profile.EffectiveIdentity().Kind
	payload := buildAlertPayload("core-sw-01", kind, "site-a", "critical", "sig-1", 0.97, 1, "network_error", nil, profile.ID, time.Now(), time.Now())
	labels := payload.Labels

	if labels["pilot_subject"] == "" {
		t.Fatal("buildAlertPayload must always set pilot_subject — normalizeSubject's first, highest-precedence case depends on it")
	}
	subjectID := labels["pilot_subject"]
	subjectKind := labels["pilot_subject_kind"]
	managed := subjectKind == SubjectKindManagedHost

	if subjectID != "core-sw-01" {
		t.Fatalf("resolved subject ID = %q, want core-sw-01", subjectID)
	}
	if subjectKind != "network_device" {
		t.Fatalf("pilot_subject_kind = %q, want network_device", subjectKind)
	}
	if managed {
		t.Fatal("an SNMP-sourced alert must never resolve to a managed subject")
	}
	if _, ok := labels["pilot_host"]; ok {
		t.Fatal("an SNMP-sourced alert must never carry pilot_host at all")
	}
	if labels["pilot_target"] != "core-sw-01" {
		t.Fatalf("pilot_target = %q, want core-sw-01 (normalizeSubject's fallback case for a raw Prometheus-rule alert with no pilot_subject, e.g. SNMPTargetDown, still needs this)", labels["pilot_target"])
	}
}

// groupingClausePattern matches a PromQL aggregation's OUTPUT grouping
// clause — `sum by (...)`, `max by (...)`, `count by (...)` — as distinct
// from a join clause (`on (...)` / `group_left(...)`), which legitimately
// names ifIndex as a join key without it ever surviving into the
// aggregation's output label set.
var groupingClausePattern = regexp.MustCompile(`\b(?:sum|max|min|count|avg)\s+by\s*\(([^)]*)\)`)

// TestNetworkDeviceProfile_DeviceLevelAggregate is
// docs/verification/snmp-monitoring-integration.md's C15 (spec §8.5's
// cardinality policy / Appendix B: device-level PromQL aggregation MUST
// happen before a sample ever reaches GroupSamplesByKey — no per-ifIndex
// series may become its own Detection Engine subject). This is a static
// property of the profile's own PromQL: every feature's OUTPUT grouping
// clause must name pilot_target (the subject), never ifIndex — ifIndex
// may appear only inside a join clause (`on (...)`), which reduces away
// before the outer aggregation's result label set is fixed.
func TestNetworkDeviceProfile_DeviceLevelAggregate(t *testing.T) {
	profile := loadNetworkDeviceProfile(t)
	if len(profile.Features) == 0 {
		t.Fatal("expected at least one feature")
	}
	for _, f := range profile.Features {
		groups := groupingClausePattern.FindAllStringSubmatch(f.PromQL, -1)
		if len(groups) == 0 {
			t.Fatalf("feature %q: promql has no sum/max/min/count/avg BY grouping clause at all — cannot prove device-level aggregation:\n%s", f.Name, f.PromQL)
		}
		for _, g := range groups {
			labels := g[1]
			if strings.Contains(labels, "ifIndex") {
				t.Errorf("feature %q: output grouping clause %q names ifIndex — this would let a per-interface series become its own subject:\n%s", f.Name, labels, f.PromQL)
			}
			if !strings.Contains(labels, "pilot_target") {
				t.Errorf("feature %q: output grouping clause %q does not group by pilot_target — the compiled result would have no subject label at all:\n%s", f.Name, labels, f.PromQL)
			}
		}
	}
}
