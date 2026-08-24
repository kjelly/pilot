package monitoring

import "testing"

func boolPtr(b bool) *bool { return &b }

func validProfiles() ProfileFile {
	return ProfileFile{Profiles: map[string]Profile{
		"storage-exporter": {JobName: "storage"},
	}}
}

func TestValidate_Valid(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas01", Address: "10.0.0.20:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles())
	if !r.OK() {
		t.Fatalf("expected valid, got errors: %v", r.Errors)
	}
}

func TestValidate_IPv6Address(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "ipv6", Address: "[2001:db8::1]:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles())
	if !r.OK() {
		t.Fatalf("expected IPv6 address to validate, got: %v", r.Errors)
	}
}

func TestValidate_InvalidAddress(t *testing.T) {
	cases := []string{"https://10.0.0.20:9100", "10.0.0.20", "nas01", ""}
	for _, addr := range cases {
		tf := TargetFile{Targets: []Target{{Name: "x", Address: addr, Profile: "storage-exporter"}}}
		r := Validate(tf, validProfiles())
		if r.OK() {
			t.Errorf("address %q: expected a validation error, got none", addr)
		}
	}
}

func TestValidate_DuplicateTargetName(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "dup", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
		{Name: "dup", Address: "10.0.0.2:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles())
	if r.OK() {
		t.Fatalf("expected duplicate name to fail validation")
	}
}

func TestValidate_MissingProfile(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas01", Address: "10.0.0.1:9100", Profile: "does-not-exist"},
	}}
	r := Validate(tf, validProfiles())
	if r.OK() {
		t.Fatalf("expected unknown-profile reference to fail validation")
	}
}

func TestValidate_ReservedLabel(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas01", Address: "10.0.0.1:9100", Profile: "storage-exporter",
			Labels: map[string]string{"pilot_source": "override-attempt"}},
	}}
	r := Validate(tf, validProfiles())
	if r.OK() {
		t.Fatalf("expected reserved label to fail validation")
	}
}

func TestValidate_ProfileJobNameRequired(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"broken": {}}}
	r := Validate(TargetFile{}, pf)
	if r.OK() {
		t.Fatalf("expected missing jobName to fail validation")
	}
}

func TestValidate_DuplicateJobName(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"a": {JobName: "storage"},
		"b": {JobName: "storage"},
	}}
	r := Validate(TargetFile{}, pf)
	if r.OK() {
		t.Fatalf("expected duplicate jobName across profiles to fail validation")
	}
}

func TestValidate_ReservedJobName(t *testing.T) {
	for _, reserved := range ReservedJobNames {
		pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: reserved}}}
		r := Validate(TargetFile{}, pf)
		if r.OK() {
			t.Errorf("jobName %q: expected reserved-name validation error", reserved)
		}
	}
}

func TestValidate_InvalidScheme(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "j", Scheme: "ftp"}}}
	r := Validate(TargetFile{}, pf)
	if r.OK() {
		t.Fatalf("expected invalid scheme to fail validation")
	}
}

func TestValidate_InvalidDuration(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "j", ScrapeInterval: "not-a-duration"}}}
	r := Validate(TargetFile{}, pf)
	if r.OK() {
		t.Fatalf("expected invalid scrapeInterval to fail validation")
	}
}

func TestValidate_InsecureSkipVerifyWarns(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"p": {JobName: "j", Scheme: "https", TLS: &TLSConfig{InsecureSkipVerify: true}},
	}}
	r := Validate(TargetFile{}, pf)
	if !r.OK() {
		t.Fatalf("insecureSkipVerify should warn, not error: %v", r.Errors)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %v", r.Warnings)
	}
}

func TestValidate_DisabledTargetSkipsProfileCheck_ButStillNamed(t *testing.T) {
	// A disabled target still needs a valid name/address — only the file_sd
	// compilation step (Compile) skips disabled targets, not Validate.
	tf := TargetFile{Targets: []Target{
		{Name: "off", Address: "10.0.0.1:9100", Profile: "storage-exporter", Enabled: boolPtr(false)},
	}}
	r := Validate(tf, validProfiles())
	if !r.OK() {
		t.Fatalf("a disabled but otherwise-valid target should still validate cleanly: %v", r.Errors)
	}
}

func TestValidate_DuplicateEndpointWarnsNotFails(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "a", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
		{Name: "b", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles())
	if !r.OK() {
		t.Fatalf("duplicate endpoint address should warn, not fail: %v", r.Errors)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("expected exactly one duplicate-endpoint warning, got %v", r.Warnings)
	}
}

func TestProfileInUse(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "a", Profile: "storage-exporter"},
		{Name: "b", Profile: "other"},
	}}
	got := ProfileInUse(tf, "storage-exporter")
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("ProfileInUse: got %v", got)
	}
	if got := ProfileInUse(tf, "unused"); len(got) != 0 {
		t.Fatalf("ProfileInUse(unused): got %v", got)
	}
}
