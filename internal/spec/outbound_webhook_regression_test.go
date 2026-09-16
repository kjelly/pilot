package spec

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestRegression_OutboundWebhookAcceptanceContract locks the structure of
// the Phase 0 acceptance contract for docs/tmp/now/spec.md ("Pilot
// Outbound State Webhook + State Projection"). C1-C30 are that spec's own
// §47 acceptance rows — silently dropping or renumbering a row here would
// desync this file from the design doc it is supposed to trace, and a
// coding agent implementing a later phase could "satisfy" a weaker
// acceptance row than the one actually agreed on.
func TestRegression_OutboundWebhookAcceptanceContract(t *testing.T) {
	const specPath = "../../docs/verification/outbound-webhook.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := make([]string, 0, 30)
	for i := 1; i <= 30; i++ {
		wantIDs = append(wantIDs, "C"+strconv.Itoa(i))
	}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// Every row must be verifyOnly: the acceptance contract itself never
	// mutates anything — a webhook subsystem probe is never the thing
	// that performs the already-selected deploy/reconcile mutation
	// (design spec Phase 0 exit criteria: "webhook subsystem itself
	// performs no infrastructure mutation").
	for _, r := range s.Rows {
		if !r.VerifyOnly {
			t.Errorf("row %s must be verifyOnly", r.ID)
		}
	}

	// No vague expected values.
	for _, r := range s.Rows {
		trimmed := strings.ToLower(strings.TrimSpace(r.Expected))
		if trimmed == "" || trimmed == "ok" || trimmed == "success" || trimmed == "true" {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// Every probe must invoke `go test ... -run <name>` against a real,
	// distinct Go test name pattern — this is a Go-feature spec (like
	// snmp-monitoring-integration.md / host-decommission.md), not an
	// infra-role spec with shell/ansible probes. No row in this file has
	// scope:per-host; the design spec's Phase 5 actual-run lanes (L1-L7)
	// are recorded separately in docs/evidence/outbound-webhook/, not as
	// rows here, once that evidence exists.
	seenProbes := map[string]string{}
	for _, r := range s.Rows {
		if !strings.Contains(r.Command, "go test") || !strings.Contains(r.Command, "-run") {
			t.Errorf("row %s probe must run `go test ... -run <pattern>`, got %q", r.ID, r.Command)
			continue
		}
		if prior, ok := seenProbes[r.Command]; ok {
			t.Errorf("row %s reuses the exact probe of row %s — every C row must assert a distinct behavior", r.ID, prior)
		}
		seenProbes[r.Command] = r.ID
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}

// outboundWebhookEffectRegex mirrors design spec §6.2's contract-effect
// naming rule: lowercase dotted segments, at least one dot, no wildcard.
var outboundWebhookEffectRegex = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// outboundWebhookKnownEffects locks the design spec §6.3 typed effect
// registry. When internal/contract grows a real Effect type in Phase 1,
// its own registry must be exactly this set — a coding agent must not
// invent an effect string ad hoc to make a test pass.
var outboundWebhookKnownEffects = []string{
	"identity.users",
	"identity.groups",
	"identity.hostgroups",
	"identity.netgroups",
	"access.hbac",
	"access.sudo",
	"access.grants",
	"dns.zones",
	"dns.records",
	"network.resolver",
	"network.endpoints",
	"trust.ca",
	"tls.certificates",
	"reverse_proxy.routes",
	"identity.freeipa_replica",
	"identity.realm_membership",
	"storage.nfs.identity",
	"monitoring.scrape_targets",
}

// outboundWebhookEffectMapping locks design spec §6.4's exact
// component -> effects mapping. This must equal the set of
// `deployCatalog` entries with `Reconcile: true` as of the design spec's
// baseline commit (13ea9be6) — cmd/pilot/cmd/deploy_catalog_effects_test.go
// (added in Phase 1) cross-checks the real contracts/*.yaml against this
// same set; if deployCatalog grows a new reconciler, both this table and
// that one must be updated together with a stated design decision, never
// guessed ad hoc by whoever is implementing that phase.
var outboundWebhookEffectMapping = map[string][]string{
	"freeipa-identity": {
		"identity.users", "identity.groups", "identity.hostgroups", "identity.netgroups",
		"access.hbac", "access.sudo", "access.grants", "storage.nfs.identity",
	},
	"freeipa-dns":               {"dns.zones", "dns.records"},
	"freeipa-dns-client":        {"network.resolver"},
	"freeipa-ca-trust":          {"trust.ca"},
	"freeipa-server-replica":    {"identity.freeipa_replica"},
	"freeipa-realm-replacement": {"identity.realm_membership"},
	"pilot-gateway-scope":       {"identity.hostgroups", "access.hbac"},
	"internal-endpoint":         {"network.endpoints", "dns.records", "tls.certificates", "reverse_proxy.routes"},
	"prometheus":                {"monitoring.scrape_targets"},
}

func TestRegression_OutboundWebhookKnownEffectRegistry(t *testing.T) {
	if len(outboundWebhookKnownEffects) != 18 {
		t.Fatalf("known effect registry size=%d want=18 (design spec §6.3)", len(outboundWebhookKnownEffects))
	}
	seen := map[string]bool{}
	for _, e := range outboundWebhookKnownEffects {
		if !outboundWebhookEffectRegex.MatchString(e) {
			t.Errorf("known effect %q does not match ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$", e)
		}
		if seen[e] {
			t.Errorf("known effect %q declared twice", e)
		}
		seen[e] = true
	}
}

func TestRegression_OutboundWebhookEffectMapping(t *testing.T) {
	wantComponents := []string{
		"freeipa-identity", "freeipa-dns", "freeipa-dns-client", "freeipa-ca-trust",
		"freeipa-server-replica", "freeipa-realm-replacement", "pilot-gateway-scope",
		"internal-endpoint", "prometheus",
	}
	if len(outboundWebhookEffectMapping) != len(wantComponents) {
		t.Fatalf("effect mapping has %d components, want %d", len(outboundWebhookEffectMapping), len(wantComponents))
	}
	known := map[string]bool{}
	for _, e := range outboundWebhookKnownEffects {
		known[e] = true
	}
	for _, c := range wantComponents {
		effects, ok := outboundWebhookEffectMapping[c]
		if !ok {
			t.Errorf("effect mapping missing component %q", c)
			continue
		}
		if len(effects) == 0 {
			t.Errorf("component %q has zero effects (design spec §6.1: every Reconcile:true entry MUST have at least one effect)", c)
		}
		sorted := append([]string(nil), effects...)
		sort.Strings(sorted)
		seen := map[string]bool{}
		for _, e := range sorted {
			if !known[e] {
				t.Errorf("component %q declares unknown effect %q", c, e)
			}
			if seen[e] {
				t.Errorf("component %q declares duplicate effect %q", c, e)
			}
			seen[e] = true
		}
	}
}

// outboundWebhookRequiredWorkflowScenarios locks design spec §46.6's W1-W20
// workflow regression scenario names, reserved ahead of Phase 4 so the
// coordinator/adapter tests it requires are named consistently with the
// probes already committed in docs/verification/outbound-webhook.md.
var outboundWebhookRequiredWorkflowScenarios = []string{
	"W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8", "W9", "W10",
	"W11", "W12", "W13", "W14", "W15", "W16", "W17", "W18", "W19", "W20",
}

func TestRegression_OutboundWebhookRequiredWorkflowScenarios(t *testing.T) {
	if len(outboundWebhookRequiredWorkflowScenarios) != 20 {
		t.Fatalf("required workflow scenario count=%d want=20", len(outboundWebhookRequiredWorkflowScenarios))
	}
	seen := map[string]bool{}
	for i, id := range outboundWebhookRequiredWorkflowScenarios {
		want := "W" + strconv.Itoa(i+1)
		if id != want {
			t.Errorf("scenario[%d]=%q want=%q (must stay in W1..W20 order)", i, id, want)
		}
		if seen[id] {
			t.Errorf("scenario %q declared twice", id)
		}
		seen[id] = true
	}
}

// outboundWebhookSecretSentinels locks design spec §46.7's fixture secret
// values. Every phase-2/3 test that builds a projection, outbox row, or
// dispatcher body from a fixture containing real-shaped secrets MUST reuse
// these exact literals (redeclared locally in that package's test file —
// this is deliberately not an importable symbol, since production code
// must never reference a "known secret shape") so the leak assertions in
// this project's C14 row are checking the same thing everywhere.
var outboundWebhookSecretSentinels = []string{
	"PILOT-SECRET-NEVER-LEAK-123",
	"ssh-ed25519 AAAA-SECRET-KEY-FIXTURE",
}

func TestRegression_OutboundWebhookSecretSentinels(t *testing.T) {
	if len(outboundWebhookSecretSentinels) != 2 {
		t.Fatalf("secret sentinel count=%d want=2 (design spec §46.7)", len(outboundWebhookSecretSentinels))
	}
	seen := map[string]bool{}
	for _, sv := range outboundWebhookSecretSentinels {
		if strings.TrimSpace(sv) == "" {
			t.Error("secret sentinel must not be blank")
		}
		if seen[sv] {
			t.Errorf("secret sentinel %q declared twice", sv)
		}
		seen[sv] = true
	}
}
