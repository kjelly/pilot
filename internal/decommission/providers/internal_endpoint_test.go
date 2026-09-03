package providers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func writeManifest(t *testing.T, dir string, allowDelete bool, endpointState string) string {
	t.Helper()
	path := filepath.Join(dir, "internal-endpoints.yaml")
	content := `
schema_version: 1
defaults:
  dns: {ttl: 300}
safety:
  allow_endpoint_delete: ` + boolYAML(allowDelete) + `
endpoints:
  - fqdn: api.ipa.pilot.internal
    state: ` + endpointState + `
    dns: {zone: ipa.pilot.internal}
    route:
      mode: direct
      target: {inventory_host: web1.ipa.pilot.internal}
    tls: {mode: freeipa}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func boolYAML(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

const endpointInspectAbsent = "ENDPOINT_INSPECT[api.ipa.pilot.internal]\nHOST_RESULT: ipa: ERROR: api.ipa.pilot.internal: host not found\nDNS_RESULT: ipa: ERROR: api: DNS resource record not found\n"
const endpointInspectPresent = "ENDPOINT_INSPECT[api.ipa.pilot.internal]\nHOST_RESULT:   Host name: api.ipa.pilot.internal\nDNS_RESULT:   A record: 192.168.1.5\n"

func TestInternalEndpointProvider_NoReferenceIsNoOp(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, true, "present")
	fake := &fakeAnsibleExecutor{}
	p := NewInternalEndpointProvider(InternalEndpointProviderConfig{Executor: fake, ManifestPath: manifest})

	steps, err := p.Plan(context.Background(), PlanInput{HostName: "unrelated-host.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if steps != nil {
		t.Fatalf("expected no steps for an unreferenced host, got %v", steps)
	}
}

func TestInternalEndpointProvider_MissingManifestIsNoOp(t *testing.T) {
	p := NewInternalEndpointProvider(InternalEndpointProviderConfig{ManifestPath: filepath.Join(t.TempDir(), "internal-endpoints.yaml")})
	steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if steps != nil {
		t.Fatalf("expected no steps when manifest does not exist, got %v", steps)
	}
}

// TestInternalEndpointProvider_RemovedOrRepointedOrBlocks is HD13's exact
// acceptance probe (docs/verification/host-decommission.md): a referenced
// endpoint is removed via the existing ledger-aware delete path when the
// manifest's own safety flag allows it, or decommission blocks when it
// doesn't.
func TestInternalEndpointProvider_RemovedOrRepointedOrBlocks(t *testing.T) {
	t.Run("blocks when safety.allow_endpoint_delete is false", func(t *testing.T) {
		dir := t.TempDir()
		manifest := writeManifest(t, dir, false, "present")
		fake := &fakeAnsibleExecutor{}
		p := NewInternalEndpointProvider(InternalEndpointProviderConfig{Executor: fake, ManifestPath: manifest})

		steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1.ipa.pilot.internal"})
		if err == nil {
			t.Fatalf("expected a blocking error, got steps=%v", steps)
		}
		if !strings.Contains(err.Error(), "allow_endpoint_delete") {
			t.Errorf("error should mention allow_endpoint_delete, got %q", err.Error())
		}
		if len(fake.calls) != 0 {
			t.Errorf("blocked Plan must not touch ansible at all, got %d calls", len(fake.calls))
		}
	})

	t.Run("removed via the existing ledger-aware delete path when allowed", func(t *testing.T) {
		dir := t.TempDir()
		manifest := writeManifest(t, dir, true, "present")

		queried := 0
		fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
			if argsContain(args, "--tags") && argsContain(args, "iep_decommission_verify") {
				queried++
				if queried == 1 {
					// Inspect (before Execute) — still present.
					return &ansible.Result{Stdout: endpointInspectPresent}, nil
				}
				// Verify (after Execute) — converged.
				return &ansible.Result{Stdout: endpointInspectAbsent}, nil
			}
			// The real apply-converge run (no --tags restriction).
			return &ansible.Result{}, nil
		}}
		p := NewInternalEndpointProvider(InternalEndpointProviderConfig{
			Executor:        fake,
			ManifestPath:    manifest,
			ServerInventory: "inventory.yml",
			ApplyPlaybook:   "playbooks/apply/internal-endpoint-apply.yml",
		})

		steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1.ipa.pilot.internal"})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if len(steps) != 2 {
			t.Fatalf("expected 2 steps, got %d: %v", len(steps), steps)
		}
		for _, step := range steps {
			if step.TargetIdentity != "api.ipa.pilot.internal" {
				t.Errorf("step %s TargetIdentity = %q, want the endpoint fqdn", step.Action, step.TargetIdentity)
			}
			se, err := p.ExecutorForStep(step)
			if err != nil {
				t.Fatalf("ExecutorForStep(%s): %v", step.Action, err)
			}
			converged, err := se.Inspect(context.Background())
			if err != nil {
				t.Fatalf("Inspect(%s): %v", step.Action, err)
			}
			if converged {
				t.Fatalf("step %s reported converged before Execute ran", step.Action)
			}
			if err := se.Execute(context.Background()); err != nil {
				t.Fatalf("Execute(%s): %v", step.Action, err)
			}
		}

		fields, found, err := readManifestEndpointState(manifest)
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		if !found || fields != "absent" {
			t.Errorf("expected the manifest entry to converge to state: absent, got found=%v state=%q", found, fields)
		}

		verifs, err := p.Verify(context.Background(), VerifyInput{FQDN: "api.ipa.pilot.internal"})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		for _, v := range verifs {
			if v.Active {
				t.Errorf("verification %s reported Active=true after cleanup: %+v", v.Kind, v)
			}
		}
	})
}

func TestInternalEndpointProvider_VerifyDetectsActiveResidue(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: endpointInspectPresent}, nil
	}}
	p := NewInternalEndpointProvider(InternalEndpointProviderConfig{Executor: fake, ApplyPlaybook: "playbooks/apply/internal-endpoint-apply.yml"})
	verifs, err := p.Verify(context.Background(), VerifyInput{FQDN: "api.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	foundActive := false
	for _, v := range verifs {
		if v.Kind == "endpoint_host_object" && v.Active {
			foundActive = true
		}
	}
	if !foundActive {
		t.Errorf("expected endpoint_host_object to report Active=true for still-present state, got %+v", verifs)
	}
}

func TestInternalEndpointProvider_AnsibleFailureIsNotTreatedAsAbsent(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 1, Stderr: "unreachable"}, nil
	}}
	p := NewInternalEndpointProvider(InternalEndpointProviderConfig{Executor: fake, ApplyPlaybook: "playbooks/apply/internal-endpoint-apply.yml"})
	if _, err := p.Verify(context.Background(), VerifyInput{FQDN: "api.ipa.pilot.internal"}); err == nil {
		t.Fatalf("expected a genuinely failed ansible-playbook run to surface as an error, not a silent pass")
	}
}

// readManifestEndpointState is a tiny test-only helper reading back what
// SetInternalEndpoint wrote, without importing the inventory package's
// unexported internals.
func readManifestEndpointState(path string) (state string, found bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	// The manifest has exactly one endpoint in these fixtures — a crude
	// substring check is enough to prove convergence without re-parsing
	// YAML here.
	text := string(data)
	if !strings.Contains(text, "fqdn: api.ipa.pilot.internal") {
		return "", false, nil
	}
	if strings.Contains(text, "state: absent") {
		return "absent", true, nil
	}
	return "present", true, nil
}

