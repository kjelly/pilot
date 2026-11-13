package spec

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// A from-scratch site-wide deploy installs pilot-access-gateway on a host whose
// FreeIPA server is built earlier in the same run. The hostgroup
// pilot-target-<scope> is published afterwards by the day-2
// `pilot gateway-scope reconcile` (which needs that server), and its ownership
// ledger refuses a hostgroup created any other way. Step 17 required
// `status: ok` and Step 18 the hostgroup, so the first apply always stopped
// there with a 503 (minimal-PoC 5-node clean-room acceptance, bastion,
// 2026-11-12). These tests run the real Step 17/18 tasks on localhost and lock
// the rule that replaced it: a gateway that will not install ForceCommand
// accepts exactly one degraded shape, every other answer still stops the run,
// and a gateway that will install ForceCommand stays strict.

// Health bodies: okBody and the unreachable body follow handleHealth in
// internal/gatewayapi/routes.go; scopeMissingBody is the answer captured from
// the real gateway on the failed first apply.
const (
	okBody = `{"status":"ok","gateway_id":"gw","gateway_scope":"all","target_hostgroup":"pilot-target-all",` +
		`"freeipa":"reachable","target_scope":"ok","credential":"ok"}`
	scopeMissingBody = `{"status":"degraded","freeipa":"reachable","credential":"ok","target_scope":"missing","target_hostgroup":"pilot-target-all"}`
	ipaDownBody      = `{"status":"degraded","gateway_id":"gw","gateway_scope":"all","target_hostgroup":"pilot-target-all",` +
		`"freeipa":"unreachable","target_scope":"missing","credential":"unknown"}`
	credentialBadBody = `{"status":"degraded","freeipa":"reachable","credential":"unknown","target_scope":"missing","target_hostgroup":"pilot-target-all"}`
)

const (
	probeTask      = "Step 17: capability probe FreeIPA via /v1/health"
	gateTask       = "Step 17: gate — health probe reports ok"
	warn17Task     = "Step 17: pilot-target-<scope> is not published yet (ForceCommand not requested)"
	assert18Task   = "Step 18: verify configured pilot-target-<scope> exists"
	warn18Task     = "Step 18: pilot-target-<scope> is not published yet (ForceCommand not requested)"
	curlConnectErr = `echo 'curl: (7) Failed to connect' >&2; exit 7`
)

func TestRegression_GatewayFirstApplyAcceptsOnlyAMissingScope(t *testing.T) {
	pb := fcPlaybooks[0]
	playVars, tasks := fcPlay(t, pb)
	want := []string{probeTask, gateTask, warn17Task, assert18Task, warn18Task}
	var keep []map[string]any
	for _, name := range want {
		var found map[string]any
		for _, task := range tasks {
			if fcName(task) == name {
				found = task
			}
		}
		if found == nil {
			t.Fatalf("task %q not found in %s", name, pb.path)
		}
		keep = append(keep, found)
	}
	probe := keep[0]
	argv := fmt.Sprint(probe["ansible.builtin.command"])
	if strings.Contains(argv, "--fail") {
		t.Errorf("the probe must not use --fail: a degraded gateway answers 503 and the body is what the rule reads: %s", argv)
	}
	if !strings.Contains(fmt.Sprint(probe["until"]), "gateway_health_acceptable") {
		t.Errorf("the probe must retry until the acceptance rule holds, got until=%v", probe["until"])
	}
	if n, _ := probe["retries"].(int); n < 3 {
		t.Errorf("the probe must keep its retries, got %v", probe["retries"])
	}

	type result struct {
		failedAt string // task name that must fail; empty means the run must pass
		warns    []string
	}
	for _, tc := range []struct {
		name         string
		forcecommand bool
		body         string
		curlFails    bool
		showRC       any // nil: Step 13's result is not defined (tag-scoped run)
		check        bool
		want         result
	}{
		// Must pass.
		{name: "no-forcecommand/healthy/scope-published", body: okBody, showRC: 0},
		{name: "no-forcecommand/healthy/show-says-absent-warns-at-18", body: okBody, showRC: 2,
			want: result{warns: []string{warn18Task}}},
		{name: "no-forcecommand/first-apply-scope-not-published-yet", body: scopeMissingBody, showRC: 2,
			want: result{warns: []string{warn17Task, warn18Task}}},
		{name: "forcecommand/healthy/scope-published", forcecommand: true, body: okBody, showRC: 0},
		{name: "check-mode-skips-every-step", body: scopeMissingBody, showRC: 2, check: true},
		// Must stop the run.
		{name: "no-forcecommand/scope-missing-but-the-group-exists", body: scopeMissingBody, showRC: 0,
			want: result{failedAt: gateTask}},
		{name: "no-forcecommand/scope-missing-and-no-independent-lookup", body: scopeMissingBody,
			want: result{failedAt: gateTask}},
		{name: "no-forcecommand/freeipa-unreachable", body: ipaDownBody, showRC: 2, want: result{failedAt: gateTask}},
		{name: "no-forcecommand/credential-not-ok", body: credentialBadBody, showRC: 2, want: result{failedAt: gateTask}},
		{name: "no-forcecommand/gateway-does-not-answer", curlFails: true, showRC: 2, want: result{failedAt: gateTask}},
		{name: "forcecommand/scope-not-published-stays-fail-closed", forcecommand: true, body: scopeMissingBody, showRC: 2,
			want: result{failedAt: gateTask}},
		{name: "forcecommand/healthy-but-hostgroup-absent", forcecommand: true, body: okBody, showRC: 2,
			want: result{failedAt: assert18Task}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tasks []map[string]any
			if tc.showRC != nil {
				tasks = append(tasks, map[string]any{
					"name":                     "Stand in for Step 13's hostgroup-show result",
					"ansible.builtin.set_fact": map[string]any{"gateway_target_hostgroup_show": map[string]any{"rc": tc.showRC}},
				})
			}
			for _, task := range keep {
				c := fcRewrite(task)
				if fcName(task) == probeTask {
					c["retries"], c["delay"] = 1, 0
				}
				tasks = append(tasks, c)
			}
			health := []any{"printf", "%s", tc.body}
			if tc.curlFails {
				health = []any{"sh", "-c", curlConnectErr}
			}
			extra := map[string]any{
				"fc_health_cmd":                             health,
				"gateway_scope":                             "all",
				"gateway_target_hostgroup":                  "pilot-target-all",
				"gateway_socket_path":                       "/run/pilot/access-gateway.sock",
				"pilot_access_gateway_install_forcecommand": tc.forcecommand,
			}
			var args []string
			if tc.check {
				args = append(args, "--check")
			}
			run := runLocalTasks(t, playVars, tasks, t.TempDir(), extra, args...)
			if tc.want.failedAt == "" {
				if run.rc != 0 {
					t.Fatalf("expected the run to pass, rc=%d failures=%v\n%s", run.rc, run.failures, run.raw)
				}
			} else {
				if run.rc == 0 || len(run.failures) == 0 {
					t.Fatalf("expected %q to stop the run, it passed\n%s", tc.want.failedAt, run.raw)
				}
				if !strings.HasPrefix(run.failures[0], tc.want.failedAt) {
					t.Fatalf("expected the run to stop at %q, got %v", tc.want.failedAt, run.failures)
				}
			}
			for _, w := range []string{warn17Task, warn18Task} {
				wantWarn := false
				for _, name := range tc.want.warns {
					wantWarn = wantWarn || name == w
				}
				if run.ran[w] != wantWarn {
					t.Errorf("task %q ran=%v, want %v", w, run.ran[w], wantWarn)
				}
			}
		})
	}
}

// The ForceCommand install path keeps its own health gate in front of the
// drop-in, so loosening Step 17 for a gateway that does not install it never
// weakens the case that redirects every portal user.
func TestRegression_GatewayForceCommandStillHasItsOwnHealthGate(t *testing.T) {
	raw, err := os.ReadFile(fcPlaybooks[0].path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, must := range []string{
		`"ForceCommand gate: pilot-access-gateway is healthy"`,
		`(gateway_forcecommand_health.stdout | from_json).status == 'ok'`,
	} {
		if !strings.Contains(text, must) {
			t.Errorf("the ForceCommand health gate lost %s", must)
		}
	}
}
