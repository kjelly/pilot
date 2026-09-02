package monitoring

import (
	"reflect"
	"testing"
)

func TestCompile_OneTarget(t *testing.T) {
	tf := TargetFile{Targets: []Target{{Name: "nas01", Address: "10.0.0.1:9100", Profile: "storage-exporter"}}}
	pf := ProfileFile{Profiles: map[string]Profile{"storage-exporter": {JobName: "storage"}}}
	got := Compile(tf, pf, "")
	want := map[string][]FileSDEntry{
		"storage": {{Targets: []string{"10.0.0.1:9100"}, Labels: map[string]string{"pilot_target": "nas01", "pilot_source": "external"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCompile_MultipleTargetsSameProfile(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas02", Address: "10.0.0.2:9100", Profile: "storage-exporter"},
		{Name: "nas01", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{"storage-exporter": {JobName: "storage"}}}
	got := Compile(tf, pf, "")
	entries := got["storage"]
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	// deterministic: sorted by target name (nas01 before nas02).
	if entries[0].Labels["pilot_target"] != "nas01" || entries[1].Labels["pilot_target"] != "nas02" {
		t.Fatalf("expected deterministic name-sorted order, got %+v", entries)
	}
}

func TestCompile_MultipleProfiles(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "a", Address: "10.0.0.1:9100", Profile: "p1"},
		{Name: "b", Address: "10.0.0.2:9187", Profile: "p2"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{
		"p1": {JobName: "job1"},
		"p2": {JobName: "job2"},
	}}
	got := Compile(tf, pf, "")
	if len(got) != 2 || len(got["job1"]) != 1 || len(got["job2"]) != 1 {
		t.Fatalf("expected two separate jobs with one entry each, got %+v", got)
	}
}

func TestCompile_LabelsAndSite(t *testing.T) {
	tf := TargetFile{Targets: []Target{{
		Name: "nas01", Address: "10.0.0.1:9100", Profile: "p", Site: "taipei",
		Labels: map[string]string{"owner": "storage", "device_type": "nas"},
	}}}
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "storage"}}}
	got := Compile(tf, pf, "")
	want := map[string]string{
		"pilot_target": "nas01", "pilot_source": "external",
		"site": "taipei", "owner": "storage", "device_type": "nas",
	}
	if !reflect.DeepEqual(got["storage"][0].Labels, want) {
		t.Fatalf("got labels %+v, want %+v", got["storage"][0].Labels, want)
	}
}

func TestCompile_DisabledTargetExcluded(t *testing.T) {
	tf := TargetFile{Targets: []Target{{Name: "off", Address: "10.0.0.1:9100", Profile: "p", Enabled: boolPtr(false)}}}
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "storage"}}}
	got := Compile(tf, pf, "")
	if len(got["storage"]) != 0 {
		t.Fatalf("expected disabled target excluded, got %+v", got["storage"])
	}
}

func TestCompile_DeterministicOutput(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "c", Address: "10.0.0.3:9100", Profile: "p"},
		{Name: "a", Address: "10.0.0.1:9100", Profile: "p"},
		{Name: "b", Address: "10.0.0.2:9100", Profile: "p"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "storage"}}}
	first := Compile(tf, pf, "")
	for i := 0; i < 10; i++ {
		if !reflect.DeepEqual(Compile(tf, pf, ""), first) {
			t.Fatalf("Compile output is not deterministic across repeated calls")
		}
	}
}

func TestCompile_ProfileWithNoTargetsYieldsEmptyArray(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "storage"}}}
	got := Compile(TargetFile{}, pf, "")
	if entries, ok := got["storage"]; !ok || entries == nil || len(entries) != 0 {
		t.Fatalf("expected an empty (non-nil) entry list for an unused profile, got %+v (ok=%v)", got["storage"], ok)
	}
}

func snmpProfileFixture() Profile {
	return Profile{
		Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
		SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
	}
}

func TestCompile_SNMP_MatchingSiteIncluded(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Site: "hq", DetectionCohort: "arista-core-7050"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{"core-switch": snmpProfileFixture()}}
	got := Compile(tf, pf, "hq")
	entries := got["snmp-core-switch"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for matching site, got %+v", entries)
	}
	want := map[string]string{
		"pilot_target": "core-sw-01", "pilot_source": "external",
		"pilot_protocol": "snmp", "pilot_subject_kind": "network_device",
		"site": "hq", "detection_cohort": "arista-core-7050",
	}
	if !reflect.DeepEqual(entries[0].Labels, want) {
		t.Fatalf("got labels %+v, want %+v", entries[0].Labels, want)
	}
}

func TestCompile_SNMP_WrongSiteExcluded(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Site: "hq"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{"core-switch": snmpProfileFixture()}}
	got := Compile(tf, pf, "branch-1")
	if len(got["snmp-core-switch"]) != 0 {
		t.Fatalf("expected wrong-site SNMP target excluded, got %+v", got["snmp-core-switch"])
	}
}

func TestCompile_SNMP_NoDetectionCohortOmitsLabel(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Site: "hq"},
	}}
	pf := ProfileFile{Profiles: map[string]Profile{"core-switch": snmpProfileFixture()}}
	got := Compile(tf, pf, "hq")
	if _, ok := got["snmp-core-switch"][0].Labels["detection_cohort"]; ok {
		t.Fatalf("expected no detection_cohort label when DetectionCohort is empty, got %+v", got["snmp-core-switch"][0].Labels)
	}
}

func TestResolve(t *testing.T) {
	tf := TargetFile{Targets: []Target{{Name: "nas01", Address: "10.0.0.1:9633", Profile: "storage-exporter"}}}
	pf := ProfileFile{Profiles: map[string]Profile{"storage-exporter": {JobName: "storage", Scheme: "https"}}}
	rt, ok := Resolve(tf, pf, "nas01")
	if !ok {
		t.Fatalf("expected Resolve to find nas01")
	}
	if rt.Scheme != "https" || rt.MetricsPath != "/metrics" {
		t.Fatalf("unexpected resolved target: %+v", rt)
	}
	if _, ok := Resolve(tf, pf, "does-not-exist"); ok {
		t.Fatalf("expected Resolve to fail for an unknown target name")
	}
}
