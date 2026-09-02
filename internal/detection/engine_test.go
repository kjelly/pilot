package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEngine_RunCycle_ColdStartProducesNoTransition is a wiring smoke test:
// a single host with a valid source reading but no baseline history and no
// cohort peers must be classified source-valid yet local-score-invalid
// (spec §18: both detectors invalid -> no transition, nothing persisted).
func TestEngine_RunCycle_ColdStartProducesNoTransition(t *testing.T) {
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%d,"0.5"]}]}}`, now)
	}))
	defer server.Close()

	profile := testProfile()
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("outcomes = %+v, want exactly 1 host", outcomes)
	}
	if !outcomes[0].Valid {
		t.Fatalf("host cycle should be source-valid (all required features present/in-range): %+v", outcomes[0])
	}
	if outcomes[0].LocalScore.Valid {
		t.Fatalf("cold start (no baseline history, no cohort peers) must be local-score-invalid: %+v", outcomes[0])
	}

	active, err := store.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("no episode should have been created on an invalid-local-score cycle: %v", active)
	}
}

// TestEngine_RunCycle_MissingRequiredFeatureSkipsHost proves the engine
// itself (not just ClassifySample in isolation) treats a host with zero
// samples for a required feature as source-invalid and never advances its
// lifecycle or touches the store.
func TestEngine_RunCycle_MissingRequiredFeatureSkipsHost(t *testing.T) {
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		query := r.URL.Query().Get("query")
		if query == "memory_used_ratio_query" {
			// Simulate this one required feature never returning any
			// series for the host at all.
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%d,"0.5"]}]}}`, now)
	}))
	defer server.Close()

	profile := testProfile()
	for i, f := range profile.Features {
		if f.Name == "memory_used_ratio" {
			profile.Features[i].PromQL = "memory_used_ratio_query"
		}
	}
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Valid {
		t.Fatalf("host with a missing required feature must be source-invalid: %+v", outcomes)
	}
}

// TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog is a regression
// test for a real cold-start deadlock: baseline history accumulation
// (e.Baselines.Observe) used to only run for hosts already in `pending`,
// which requires local.Valid==true — but baseline only becomes Valid
// after 120 buckets of Observe'd history (spec §14.1), production wires
// no cohort assignment mechanism at all (Cohorts is always nil, so
// cohort-outlier-v1 is permanently Valid=false), and here the log source
// is disabled too. Before the fix, local.Valid could NEVER become true
// even once, so this test would loop 120 times and still see
// LocalScore.Valid==false on cycle 121 — the detector could never engage
// in a stock, log-source-disabled deployment.
func TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog(t *testing.T) {
	value := "0.5"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := r.URL.Query().Get("time")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%s,%q]}]}}`, at, value)
	}))
	defer server.Close()

	profile := testProfile()
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil) // cohorts=nil, matches production; LogSource left nil too

	base := (int64(1_700_000_000) / 60) * 60
	for i := 0; i < minReadyBuckets; i++ {
		evalTime := base + int64(i)*60
		outcomes, err := engine.RunCycle(context.Background(), evalTime)
		if err != nil {
			t.Fatalf("RunCycle cycle %d: %v", i, err)
		}
		if outcomes[0].LocalScore.Valid {
			t.Fatalf("cycle %d: LocalScore already Valid with only %d prior observations — expected still warming up", i, i)
		}
	}

	// The 121st cycle: 120 prior cycles have now been Observed, so
	// robust-baseline-v1 should have just become Ready.
	outcomes, err := engine.RunCycle(context.Background(), base+int64(minReadyBuckets)*60)
	if err != nil {
		t.Fatalf("RunCycle final cycle: %v", err)
	}
	if !outcomes[0].LocalScore.Valid {
		t.Fatal("after 120 warm cycles with no cohort/log rescue, LocalScore must be Valid — this is exactly the cold-start deadlock this test guards against")
	}

	// And it must actually be usable: a clear spike now scores high.
	value = "0.99"
	outcomes, err = engine.RunCycle(context.Background(), base+int64(minReadyBuckets+1)*60)
	if err != nil {
		t.Fatalf("RunCycle spike cycle: %v", err)
	}
	if !outcomes[0].LocalScore.Valid || outcomes[0].LocalScore.Score < 0.9 {
		t.Fatalf("spike cycle: LocalScore = %+v, want Valid with a high score", outcomes[0].LocalScore)
	}
}

// TestBuildAlertPayload_ManagedHostRetainsPilotHost is the Phase 4 exit
// gate's "managed host alert retains pilot_host": the generic
// pilot_subject/pilot_subject_kind labels must be present ALONGSIDE the
// legacy pilot_host label, not instead of it, for a managed_host subject.
func TestBuildAlertPayload_ManagedHostRetainsPilotHost(t *testing.T) {
	now := time.Now()
	payload := buildAlertPayload("web-1", SubjectKindManagedHost, "site-a", "critical", "sig-1", 0.9, 1, "cpu", nil, "linux-host-v1", now, now)
	if payload.Labels["pilot_host"] != "web-1" {
		t.Errorf("pilot_host = %q, want web-1", payload.Labels["pilot_host"])
	}
	if payload.Labels["pilot_subject"] != "web-1" || payload.Labels["pilot_subject_kind"] != SubjectKindManagedHost {
		t.Errorf("generic subject labels missing/wrong: %+v", payload.Labels)
	}
	if _, ok := payload.Labels["pilot_target"]; ok {
		t.Errorf("a managed_host subject must never carry pilot_target: %+v", payload.Labels)
	}
}

// TestBuildAlertPayload_NonManagedSubjectNeverGetsPilotHost is the Phase 4
// exit gate's "SNMP subject never gets pilot_host": any non-managed-host
// kind gets pilot_target instead, never the legacy pilot_host label.
func TestBuildAlertPayload_NonManagedSubjectNeverGetsPilotHost(t *testing.T) {
	now := time.Now()
	payload := buildAlertPayload("core-sw-01", "network_device", "site-a", "critical", "sig-1", 0.9, 1, "network_error", nil, "network-device-ifmib-v1", now, now)
	if _, ok := payload.Labels["pilot_host"]; ok {
		t.Errorf("a non-managed-host subject must never carry pilot_host: %+v", payload.Labels)
	}
	if payload.Labels["pilot_target"] != "core-sw-01" {
		t.Errorf("pilot_target = %q, want core-sw-01", payload.Labels["pilot_target"])
	}
	if payload.Labels["pilot_subject"] != "core-sw-01" || payload.Labels["pilot_subject_kind"] != "network_device" {
		t.Errorf("generic subject labels missing/wrong: %+v", payload.Labels)
	}
}

// TestGroupSamplesByKey_SNMPSubjectKeyNeverAssignsPilotHost is
// docs/verification/snmp-monitoring-integration.md's C7: an SNMP-shaped
// identity profile (Label=pilot_target, Kind=network_device) must
// classify a sample under that subject's own SubjectKey — its Kind must
// never come out as SubjectKindManagedHost, and its own identity label
// name is never `pilot_host`.
func TestGroupSamplesByKey_SNMPSubjectKeyNeverAssignsPilotHost(t *testing.T) {
	identity := IdentityProfile{Label: "pilot_target", Kind: "network_device", SiteLabel: "site"}
	metrics := []map[string]string{{"pilot_target": "core-sw-01", "site": "site-a", "pilot_host": "should-be-ignored"}}
	samples := []RawSample{{Timestamp: 1000, Value: 1}}
	grouped, _ := GroupSamplesByKey(metrics, samples, identity)
	if len(grouped) != 1 {
		t.Fatalf("expected exactly one subject, got %+v", grouped)
	}
	for key := range grouped {
		if key.PilotHost != "core-sw-01" {
			t.Fatalf("subject ID = %q, want core-sw-01 (from pilot_target, not the stray pilot_host label)", key.PilotHost)
		}
	}
	subject := SubjectKey{ID: "core-sw-01", Kind: identity.Kind, Site: "site-a"}
	if subject.IsManagedHost() {
		t.Fatal("an SNMP profile's SubjectKey must never classify as managed_host")
	}
}

// TestFingerprint_DifferentKindsNeverCollide guards spec §9.8's
// requirement that subject_kind participate in the fingerprint — without
// it, a managed host and an SNMP device that happened to share an ID
// string would silently alias the same SignalEvent/episode.
func TestFingerprint_DifferentKindsNeverCollide(t *testing.T) {
	a := Fingerprint("core-sw-01", SubjectKindManagedHost, "site-a", "linux-host-v1", 1)
	b := Fingerprint("core-sw-01", "network_device", "site-a", "linux-host-v1", 1)
	if a == b {
		t.Fatal("fingerprints for the same ID string under different subject kinds must never collide")
	}
}

// TestGroupSamplesByKey_MissingIdentityLabelIsDropped is spec §9.4 rule 1:
// a series whose identity label is empty can never be attributed to any
// subject.
func TestGroupSamplesByKey_MissingIdentityLabelIsDropped(t *testing.T) {
	identity := defaultIdentityProfile()
	metrics := []map[string]string{{"site": "site-a"}} // no pilot_host label at all
	samples := []RawSample{{Timestamp: 1000, Value: 1}}
	grouped, _ := GroupSamplesByKey(metrics, samples, identity)
	if len(grouped) != 0 {
		t.Fatalf("expected the identity-less series to be dropped, got %+v", grouped)
	}
}

// TestGroupSamplesByKey_NonManagedHostRequiresSiteLabel is spec §9.4 rule
// 2: an empty site is only tolerated for legacy managed-host
// compatibility — any other kind must treat a missing site as invalid.
func TestGroupSamplesByKey_NonManagedHostRequiresSiteLabel(t *testing.T) {
	identity := IdentityProfile{Label: "pilot_target", Kind: "network_device", SiteLabel: "site"}
	metrics := []map[string]string{{"pilot_target": "core-sw-01"}} // no site label
	samples := []RawSample{{Timestamp: 1000, Value: 1}}
	grouped, _ := GroupSamplesByKey(metrics, samples, identity)
	if len(grouped) != 0 {
		t.Fatalf("expected the site-less non-managed-host series to be dropped, got %+v", grouped)
	}

	managedIdentity := defaultIdentityProfile()
	metricsManaged := []map[string]string{{"pilot_host": "web-1"}} // no site label either
	groupedManaged, _ := GroupSamplesByKey(metricsManaged, samples, managedIdentity)
	if len(groupedManaged) != 1 {
		t.Fatalf("a managed-host series with an empty site must still be kept (legacy compatibility), got %+v", groupedManaged)
	}
}

// TestGroupSamplesByKey_CohortComesFromCompilerControlledLabel is spec
// §9.6: when a profile configures a cohortLabel, cohort membership comes
// directly from that label's value on the sample, never a static lookup.
func TestGroupSamplesByKey_CohortComesFromCompilerControlledLabel(t *testing.T) {
	identity := IdentityProfile{Label: "pilot_target", Kind: "network_device", SiteLabel: "site", CohortLabel: "detection_cohort"}
	metrics := []map[string]string{
		{"pilot_target": "core-sw-01", "site": "site-a", "detection_cohort": "edge-switches"},
		{"pilot_target": "core-sw-02", "site": "site-a"}, // no cohort label value at all
	}
	samples := []RawSample{{Timestamp: 1000, Value: 1}, {Timestamp: 1000, Value: 2}}
	grouped, cohorts := GroupSamplesByKey(metrics, samples, identity)
	if len(grouped) != 2 {
		t.Fatalf("expected both subjects kept, got %+v", grouped)
	}
	key1 := SeriesKey{PilotHost: "core-sw-01", Site: "site-a"}
	if cohorts[key1] != "edge-switches" {
		t.Errorf("cohort for core-sw-01 = %q, want edge-switches", cohorts[key1])
	}
	key2 := SeriesKey{PilotHost: "core-sw-02", Site: "site-a"}
	if _, ok := cohorts[key2]; ok {
		t.Errorf("a missing cohort label must never be guessed/defaulted, got %q", cohorts[key2])
	}
}
