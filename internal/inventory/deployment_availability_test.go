package inventory

import (
	"strings"
	"testing"
)

func TestEffectiveDeploymentAvailability_DefaultsToRequired(t *testing.T) {
	h := Host{Name: "web-1"}
	if got := h.EffectiveDeploymentAvailability(); got != DeploymentAvailabilityRequired {
		t.Fatalf("empty policy = %q, want required", got)
	}
}

func TestEffectiveDeploymentAvailability_ExplicitValues(t *testing.T) {
	cases := []struct {
		set  DeploymentAvailability
		want DeploymentAvailability
	}{
		{DeploymentAvailabilityRequired, DeploymentAvailabilityRequired},
		{DeploymentAvailabilityOptional, DeploymentAvailabilityOptional},
	}
	for _, c := range cases {
		h := Host{Name: "x", DeploymentAvailability: c.set}
		if got := h.EffectiveDeploymentAvailability(); got != c.want {
			t.Errorf("policy %q = %q, want %q", c.set, got, c.want)
		}
	}
}

func TestParse_DeploymentAvailability(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  ipa-1:
    ansible_host: "10.0.0.10"
    roles: [freeipa-server, dns, ntp]
  dev-vm-01:
    ansible_host: "10.0.0.31"
    roles: [freeipa-client, linux-servers]
    deployment_availability: optional
`))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Host{}
	for _, h := range hf.Hosts {
		byName[h.Name] = h
	}

	if got := byName["ipa-1"].DeploymentAvailability; got != "" {
		t.Errorf("ipa-1 deployment_availability = %q, want empty (unset)", got)
	}
	if got := byName["ipa-1"].EffectiveDeploymentAvailability(); got != DeploymentAvailabilityRequired {
		t.Errorf("ipa-1 effective policy = %q, want required", got)
	}
	if got := byName["dev-vm-01"].DeploymentAvailability; got != DeploymentAvailabilityOptional {
		t.Errorf("dev-vm-01 deployment_availability = %q, want optional", got)
	}
	// deployment_availability must be a first-class field, not dumped into Extra.
	if _, ok := byName["dev-vm-01"].Extra["deployment_availability"]; ok {
		t.Errorf("deployment_availability leaked into Extra: %v", byName["dev-vm-01"].Extra)
	}
}

func TestLint_DeploymentAvailability(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"omitted", "", false},
		{"required", "required", false},
		{"optional", "optional", false},
		{"invalid", "sometimes", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
`
			if c.value != "" {
				src += "    deployment_availability: " + c.value + "\n"
			}
			hf, err := Parse([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			issues := Lint(hf)
			if got := HasErrors(issues); got != c.wantErr {
				t.Fatalf("HasErrors() = %v, want %v (issues: %v)", got, c.wantErr, issues)
			}
		})
	}
}

func TestGenerate_DeploymentAvailability(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  ipa-1:
    ansible_host: "10.0.0.10"
    freeipa_roster_file: ".vault/ipa-identity.yaml"
    roles: [freeipa-server, dns, ntp]
  dev-vm-01:
    ansible_host: "10.0.0.31"
    roles: [freeipa-client, linux-servers]
    deployment_availability: optional
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	if want := `deployment_availability: "optional"`; !strings.Contains(out, want) {
		t.Fatalf("generated output missing %q:\n%s", want, out)
	}

	// A host that never set the field must not have it force-rendered — the
	// effective default belongs in pilot logic, not a destructive inventory
	// rewrite (spec §7.5).
	ipaBlock := out[strings.Index(out, "ipa-1:"):]
	ipaBlock = ipaBlock[:strings.Index(ipaBlock, "dev-vm-01:")]
	if strings.Contains(ipaBlock, "deployment_availability") {
		t.Fatalf("ipa-1 got a force-rendered deployment_availability:\n%s", ipaBlock)
	}
}

func TestGenerate_DeploymentAvailability_PreservesUnknownExtraFields(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  dev-vm-01:
    ansible_host: "10.0.0.31"
    roles: [linux-servers]
    deployment_availability: optional
    some_unknown_var: "keep-me"
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `some_unknown_var: "keep-me"`) {
		t.Fatalf("generated output dropped unknown extra field:\n%s", out)
	}
}
