package inventory

import (
	"regexp"
	"strings"
	"testing"
)

// --- 23.1 Parser ---------------------------------------------------------

func TestParse_NoAnnotations(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(hf.Hosts[0].Annotations) != 0 {
		t.Errorf("Annotations = %v, want empty", hf.Hosts[0].Annotations)
	}
}

func TestParse_OneAnnotation(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := hf.Hosts[0].Annotations["project"]; got != "alpha" {
		t.Errorf("annotations[project] = %q, want alpha", got)
	}
}

func TestParse_MultipleAnnotations(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
      owner: "platform"
      location: "DC1"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(hf.Hosts[0].Annotations) != 3 {
		t.Errorf("Annotations = %v, want 3 entries", hf.Hosts[0].Annotations)
	}
}

func TestParse_AnnotationUnicodeValue(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      note: "台北機房/DC1/Rack-A03/U18"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := hf.Hosts[0].Annotations["note"]; got != "台北機房/DC1/Rack-A03/U18" {
		t.Errorf("annotations[note] = %q", got)
	}
}

func TestParse_AnnotationValueWithEquals(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      note: "owner=AI Platform"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := hf.Hosts[0].Annotations["note"]; got != "owner=AI Platform" {
		t.Errorf("annotations[note] = %q", got)
	}
}

func TestParse_AnnotationRejectsNonStringInt(t *testing.T) {
	if _, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: 123
`)); err == nil {
		t.Fatal("expected an error for an int annotation value")
	}
}

func TestParse_AnnotationRejectsBool(t *testing.T) {
	if _, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      enabled: true
`)); err == nil {
		t.Fatal("expected an error for a bool annotation value")
	}
}

func TestParse_AnnotationRejectsList(t *testing.T) {
	if _, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      projects:
        - alpha
        - beta
`)); err == nil {
		t.Fatal("expected an error for a list annotation value")
	}
}

func TestParse_AnnotationRejectsNestedMap(t *testing.T) {
	if _, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      owner:
        team: ai
`)); err == nil {
		t.Fatal("expected an error for a nested-map annotation value")
	}
}

func TestParse_AnnotationsNotCopiedIntoExtra(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hf.Hosts[0].Extra["annotations"]; ok {
		t.Error("annotations leaked into Extra")
	}
	if _, ok := hf.Hosts[0].Extra["project"]; ok {
		t.Error("annotation key leaked into Extra")
	}
}

func TestParse_ExistingExtraUnchangedByAnnotations(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    some_ansible_var: "keep-me"
    annotations:
      project: "alpha"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := hf.Hosts[0].Extra["some_ansible_var"]; got != "keep-me" {
		t.Errorf("Extra[some_ansible_var] = %q, want keep-me", got)
	}
	if _, ok := hf.Hosts[0].Annotations["some_ansible_var"]; ok {
		t.Error("Extra key leaked into Annotations")
	}
}

// --- 23.2 Validation -------------------------------------------------------

func TestValidateAnnotationKey_Accepted(t *testing.T) {
	for _, key := range []string{"location", "project", "project.phase", "asset_tag", "cost-center", "owner.team"} {
		if err := ValidateAnnotationKey(key); err != nil {
			t.Errorf("ValidateAnnotationKey(%q) = %v, want accepted", key, err)
		}
	}
}

func TestValidateAnnotationKey_Rejected(t *testing.T) {
	for _, key := range []string{"Location", "PROJECT", "_foo", "foo/bar", "foo bar", ""} {
		if err := ValidateAnnotationKey(key); err == nil {
			t.Errorf("ValidateAnnotationKey(%q) = nil, want rejected", key)
		}
	}
}

func TestValidateAnnotationKey_RejectsSecretLike(t *testing.T) {
	for _, key := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "credential", "credentials",
		"service.api_key", "project.secret",
	} {
		if err := ValidateAnnotationKey(key); err == nil {
			t.Errorf("ValidateAnnotationKey(%q) = nil, want rejected as secret-like", key)
		}
	}
}

func TestValidateAnnotationValue_EmptyRejected(t *testing.T) {
	if err := ValidateAnnotationValue(""); err == nil {
		t.Fatal("expected empty value to be rejected")
	}
}

func TestValidateAnnotationValue_WhitespaceRejected(t *testing.T) {
	if err := ValidateAnnotationValue(" alpha "); err == nil {
		t.Fatal("expected leading/trailing whitespace to be rejected")
	}
}

func TestValidateAnnotationValue_NewlineRejected(t *testing.T) {
	if err := ValidateAnnotationValue("alpha\nbeta"); err == nil {
		t.Fatal("expected embedded newline to be rejected")
	}
}

func TestSerializeAnnotation_ExactlyAtLimitAccepted(t *testing.T) {
	// "pilot.annotation." (18 bytes) + key + "=" + value == 256 bytes exactly.
	key := "k"
	value := strings.Repeat("a", 256-len(AnnotationUserClassPrefix)-len(key)-1)
	if _, err := SerializeAnnotation(key, value); err != nil {
		t.Fatalf("SerializeAnnotation at exactly 256 bytes: %v", err)
	}
}

func TestSerializeAnnotation_OverLimitRejected(t *testing.T) {
	key := "k"
	value := strings.Repeat("a", 256-len(AnnotationUserClassPrefix)-len(key)-1+1)
	if _, err := SerializeAnnotation(key, value); err == nil {
		t.Fatal("expected a 257-byte serialized annotation to be rejected")
	}
}

func TestValidateAnnotations_MaxCountAccepted(t *testing.T) {
	annotations := make(map[string]string, MaxAnnotationsPerHost)
	for i := 0; i < MaxAnnotationsPerHost; i++ {
		annotations[keyN(i)] = "v"
	}
	if errs := ValidateAnnotations(annotations); len(errs) != 0 {
		t.Errorf("32 annotations rejected: %v", errs)
	}
}

func TestValidateAnnotations_OverMaxCountRejected(t *testing.T) {
	annotations := make(map[string]string, MaxAnnotationsPerHost+1)
	for i := 0; i < MaxAnnotationsPerHost+1; i++ {
		annotations[keyN(i)] = "v"
	}
	if errs := ValidateAnnotations(annotations); len(errs) == 0 {
		t.Fatal("expected 33 annotations to be rejected")
	}
}

func keyN(i int) string {
	return "k" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
}

// --- 23.3 Render ------------------------------------------------------------

func TestRender_AnnotationsSorted(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
      asset_tag: "IT-1"
      owner: "platform"
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := "    annotations:\n      asset_tag: \"IT-1\"\n      owner: \"platform\"\n      project: \"alpha\"\n"
	if !strings.Contains(out, wantOrder) {
		t.Errorf("annotations not sorted, got:\n%s", out)
	}
}

func TestRender_AnnotationsDeterministic(t *testing.T) {
	src := []byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
      owner: "platform"
`)
	hf1, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	hf2, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	out1, err := Render(hf1)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := Render(hf2)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Errorf("Render is not deterministic:\n%s\nvs\n%s", out1, out2)
	}
}

func TestRender_AnnotationsRoundTrip(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      project: "alpha"
      note: "台北 DC owner=AI Platform"
`))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	hf2, err := Parse([]byte(rendered))
	if err != nil {
		t.Fatalf("re-parsing rendered output failed: %v\n%s", err, rendered)
	}
	if hf2.Hosts[0].Annotations["project"] != "alpha" {
		t.Errorf("project lost in round-trip: %v", hf2.Hosts[0].Annotations)
	}
	if hf2.Hosts[0].Annotations["note"] != "台北 DC owner=AI Platform" {
		t.Errorf("note lost in round-trip: %v", hf2.Hosts[0].Annotations)
	}
}

func TestRender_OldHostsFileWithoutAnnotationsUnaffected(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "annotations:") {
		t.Errorf("unexpected annotations block for a host without any:\n%s", out)
	}
}

func TestRender_ExtraAndAnnotationsCoexist(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    some_ansible_var: "keep-me"
    annotations:
      project: "alpha"
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "some_ansible_var: \"keep-me\"\n") {
		t.Errorf("missing Extra field:\n%s", out)
	}
	if !strings.Contains(out, "annotations:\n      project: \"alpha\"\n") {
		t.Errorf("missing annotations block:\n%s", out)
	}
}

// --- 23.4 Generate -----------------------------------------------------------

func TestGenerate_AnnotationsProjectToPilotAnnotationsHostVar(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      location: "DC1"
      project: "alpha"
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "      pilot_annotations:\n        location: \"DC1\"\n        project: \"alpha\"\n") {
		t.Errorf("missing pilot_annotations block:\n%s", out)
	}
	// location/project MUST NEVER appear as top-level host vars — i.e. at
	// the same 6-space indent as ansible_host, not merely somewhere in the
	// output (an 8-space-indented nested line would also satisfy a plain
	// substring check, since indentation is just repeated spaces).
	topLevelHostVar := regexp.MustCompile(`(?m)^      (location|project): `)
	if topLevelHostVar.MatchString(out) {
		t.Errorf("annotation key leaked as a top-level host var:\n%s", out)
	}
}

func TestGenerate_EmptyAnnotationsOmitsPilotAnnotationsKey(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "pilot_annotations") {
		t.Errorf("unexpected pilot_annotations for a host without any:\n%s", out)
	}
}

func TestLint_AnnotationsClean(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      location: "DC1"
`))
	if err != nil {
		t.Fatal(err)
	}
	if issues := Lint(hf); HasErrors(issues) {
		t.Fatalf("unexpected lint errors: %v", issues)
	}
}

func TestLint_AnnotationsInvalidKeyIsError(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      Location: "DC1"
`))
	if err != nil {
		t.Fatal(err)
	}
	if issues := Lint(hf); !HasErrors(issues) {
		t.Fatal("expected an error for an invalid annotation key")
	}
}

func TestLint_AnnotationsSecretKeyIsError(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    annotations:
      api_key: "abc123"
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if !HasErrors(issues) {
		t.Fatal("expected an error for a secret-like annotation key")
	}
	found := false
	for _, i := range issues {
		if strings.Contains(i.Message, "secret-bearing") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a secret-bearing message, got %v", issues)
	}
}
