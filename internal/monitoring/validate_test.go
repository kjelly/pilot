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
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if !r.OK() {
		t.Fatalf("expected valid, got errors: %v", r.Errors)
	}
}

func TestValidate_IPv6Address(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "ipv6", Address: "[2001:db8::1]:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if !r.OK() {
		t.Fatalf("expected IPv6 address to validate, got: %v", r.Errors)
	}
}

func TestValidate_InvalidAddress(t *testing.T) {
	cases := []string{"https://10.0.0.20:9100", "10.0.0.20", "nas01", ""}
	for _, addr := range cases {
		tf := TargetFile{Targets: []Target{{Name: "x", Address: addr, Profile: "storage-exporter"}}}
		r := Validate(tf, validProfiles(), SNMPCatalog{})
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
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected duplicate name to fail validation")
	}
}

func TestValidate_MissingProfile(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas01", Address: "10.0.0.1:9100", Profile: "does-not-exist"},
	}}
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected unknown-profile reference to fail validation")
	}
}

func TestValidate_ReservedLabel(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "nas01", Address: "10.0.0.1:9100", Profile: "storage-exporter",
			Labels: map[string]string{"pilot_source": "override-attempt"}},
	}}
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected reserved label to fail validation")
	}
}

func TestValidate_ProfileJobNameRequired(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"broken": {}}}
	r := Validate(TargetFile{}, pf, SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected missing jobName to fail validation")
	}
}

func TestValidate_DuplicateJobName(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"a": {JobName: "storage"},
		"b": {JobName: "storage"},
	}}
	r := Validate(TargetFile{}, pf, SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected duplicate jobName across profiles to fail validation")
	}
}

func TestValidate_ReservedJobName(t *testing.T) {
	for _, reserved := range ReservedJobNames {
		pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: reserved}}}
		r := Validate(TargetFile{}, pf, SNMPCatalog{})
		if r.OK() {
			t.Errorf("jobName %q: expected reserved-name validation error", reserved)
		}
	}
}

func TestValidate_InvalidScheme(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "j", Scheme: "ftp"}}}
	r := Validate(TargetFile{}, pf, SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected invalid scheme to fail validation")
	}
}

func TestValidate_InvalidDuration(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{"p": {JobName: "j", ScrapeInterval: "not-a-duration"}}}
	r := Validate(TargetFile{}, pf, SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected invalid scrapeInterval to fail validation")
	}
}

func TestValidate_InsecureSkipVerifyWarns(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"p": {JobName: "j", Scheme: "https", TLS: &TLSConfig{InsecureSkipVerify: true}},
	}}
	r := Validate(TargetFile{}, pf, SNMPCatalog{})
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
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if !r.OK() {
		t.Fatalf("a disabled but otherwise-valid target should still validate cleanly: %v", r.Errors)
	}
}

func TestValidate_DuplicateEndpointWarnsNotFails(t *testing.T) {
	tf := TargetFile{Targets: []Target{
		{Name: "a", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
		{Name: "b", Address: "10.0.0.1:9100", Profile: "storage-exporter"},
	}}
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if !r.OK() {
		t.Fatalf("duplicate endpoint address should warn, not fail: %v", r.Errors)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("expected exactly one duplicate-endpoint warning, got %v", r.Warnings)
	}
}

func snmpCatalogFixture() SNMPCatalog {
	return SNMPCatalog{
		SchemaVersion: SNMPCatalogSchemaVersion,
		Modules:       map[string]SNMPModule{"if_mib": {File: "generated/if_mib.yml"}},
		AuthProfiles: map[string]SNMPAuthProfile{
			"core-switch-v3": {Version: 3, SecurityLevel: "authPriv", CredentialRef: "core-switch-v3"},
		},
	}
}

func TestValidate_SNMPProfile_Valid(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	tf := TargetFile{Targets: []Target{
		{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Site: "hq"},
	}}
	r := Validate(tf, pf, snmpCatalogFixture())
	if !r.OK() {
		t.Fatalf("expected valid SNMP profile+target, got errors: %v", r.Errors)
	}
}

func TestValidate_SNMPProfile_BareAddressAllowed(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	for _, addr := range []string{"10.20.0.11", "udp://10.20.0.12:161", "switch.internal"} {
		tf := TargetFile{Targets: []Target{{Name: "x", Address: addr, Profile: "core-switch", Site: "hq"}}}
		r := Validate(tf, pf, snmpCatalogFixture())
		if !r.OK() {
			t.Errorf("SNMP address %q should validate, got errors: %v", addr, r.Errors)
		}
	}
}

func TestValidate_SNMPProfile_RejectsHTTPPathInAddress(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	tf := TargetFile{Targets: []Target{{Name: "x", Address: "http://10.20.0.11/path", Profile: "core-switch", Site: "hq"}}}
	r := Validate(tf, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected an HTTP-path-shaped SNMP address to fail validation")
	}
}

func TestValidate_SNMPProfile_MissingSNMPBlock(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device"},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected missing snmp block to fail validation")
	}
}

func TestValidate_SNMPProfile_EmptyModules(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected empty snmp.modules to fail validation")
	}
}

func TestValidate_SNMPProfile_DuplicateModule(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib", "if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected duplicate module to fail validation")
	}
}

func TestValidate_SNMPProfile_UnknownModule(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"does-not-exist"}, AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected unknown module reference to fail validation")
	}
}

func TestValidate_SNMPProfile_UnknownAuthProfile(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "does-not-exist"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected unknown authProfile reference to fail validation")
	}
}

func TestValidate_SNMPProfile_MissingSubjectKind(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected missing subjectKind to fail validation")
	}
}

func TestValidate_SNMPProfile_RejectsHTTPFields(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device", Scheme: "https",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected scheme set on a kind:snmp profile to fail validation")
	}
}

func TestValidate_PrometheusProfile_RejectsSNMPBlock(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"p": {JobName: "j", SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"}},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected kind:prometheus with a non-empty snmp block to fail validation")
	}
}

func TestValidate_SNMPProfile_ScrapeTimeoutMustBeLessThanInterval(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			ScrapeInterval: "30s", ScrapeTimeout: "30s",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	r := Validate(TargetFile{}, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected scrapeTimeout == scrapeInterval to fail validation")
	}
}

func TestValidate_SNMPTarget_EnabledRequiresSite(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	tf := TargetFile{Targets: []Target{{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch"}}}
	r := Validate(tf, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected an enabled SNMP target with no site to fail validation")
	}
}

func TestValidate_SNMPTarget_DisabledSiteNotRequired(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	tf := TargetFile{Targets: []Target{{Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Enabled: boolPtr(false)}}}
	r := Validate(tf, pf, snmpCatalogFixture())
	if !r.OK() {
		t.Fatalf("a disabled SNMP target should not require site: %v", r.Errors)
	}
}

func TestValidate_DetectionCohortReservedLabel(t *testing.T) {
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {
			Kind: "snmp", JobName: "snmp-core-switch", SubjectKind: "network_device",
			SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "core-switch-v3"},
		},
	}}
	tf := TargetFile{Targets: []Target{{
		Name: "core-sw-01", Address: "10.20.0.11", Profile: "core-switch", Site: "hq",
		Labels: map[string]string{"detection_cohort": "override-attempt"},
	}}}
	r := Validate(tf, pf, snmpCatalogFixture())
	if r.OK() {
		t.Fatalf("expected detection_cohort as a user label to fail validation (reserved)")
	}
}

func TestValidate_DunderLabelRejected(t *testing.T) {
	tf := TargetFile{Targets: []Target{{
		Name: "nas01", Address: "10.0.0.1:9100", Profile: "storage-exporter",
		Labels: map[string]string{"__meta_foo": "x"},
	}}}
	r := Validate(tf, validProfiles(), SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected a __-prefixed user label to fail validation")
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
