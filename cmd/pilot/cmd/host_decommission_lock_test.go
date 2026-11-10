package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/sshdial"
)

// When a decommission takes the FreeIPA identity lock
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.2,
// §4.5, E41): D1 says after the confirmation and before the first thing that
// changes anything, and the first change a decommission makes is the client's
// uninstall, several steps before the converge that runs the identity playbook.
// The lock used to be taken at the converge, so a lock that was busy, a wait that
// ran out or an interrupt came after the client had been uninstalled and the
// roster entry tombstoned. runHostDecommissionApply now takes it once, after the
// approval and before decommission.Apply, and holds it for the whole run.
//
// These tests drive that function the way the commands do (the cobra commands,
// and the function itself where a test needs to cancel its context) over a real
// workspace, the real planner and freshness check, the real executor and the real
// FreeIPA client provider. Only the outside world is replaced: a fake
// ansible-playbook that models the client and the FreeIPA server as files (what it
// prints is the shape the provider's own fixtures were captured in), and the lock,
// which is a fake in memory except in the one test that uses the production
// acquirer over a real flock. Every step that changes something writes to one
// timeline together with the lock's own events.

const decommissionLockFQDN = "client1.ipa.pilot.internal"

// fakeFreeIPAPlaybook models the two machines a freeipa-client decommission
// touches. The client is enrolled until the uninstall playbook has run; the
// server holds the host object until the identity apply playbook has run as the
// converge. The read-only host_absent_inspect queries answer from that state in
// the shapes the provider parses (see internal/decommission/providers tests).
// Anything else it is asked to run is an error: the decommission runs nothing
// else for this workspace.
const fakeFreeIPAPlaybook = `#!/bin/sh
state='@STATE@'
events='@EVENTS@'
playbook=$(basename "$1")
all="$*"
field() { printf '%s' "$all" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
case "$playbook" in
freeipa-client-decommission.yml)
  case "$all" in
  *"--tags inspect"*)
    if [ -f "$state/uninstalled" ]; then echo 'IPA_CLIENT_ENROLLED=false'; else echo 'IPA_CLIENT_ENROLLED=true'; fi ;;
  *)
    echo "client uninstall" >> "$events"
    if [ -f "$state/block-uninstall" ]; then
      touch "$state/uninstall-running"
      while [ ! -f "$state/release-uninstall" ]; do sleep 0.05; done
    fi
    touch "$state/uninstalled" ;;
  esac ;;
freeipa-identity-apply.yml)
  q=$(field pilot_decommission_query)
  fqdn=$(field pilot_decommission_target_fqdn)
  if [ -z "$q" ]; then
    case "$all" in
    *pilot_decommission_retiring_alias*) ;;
    *) echo "unexpected identity apply: $all" >&2; exit 3 ;;
    esac
    echo "identity converge" >> "$events"
    touch "$state/converged"
    exit 0
  fi
  case "$q" in
  host_object)
    if [ -f "$state/converged" ]; then
      echo "HOST_INSPECT[$fqdn]: ipa: ERROR: $fqdn: host not found"
    else
      printf 'HOST_INSPECT[%s]:   Host name: %s\n  Principal name: host/%s@IPA.PILOT.INTERNAL\n----------------------\n0 services matched\n----------------------\n' "$fqdn" "$fqdn" "$fqdn"
    fi ;;
  host_dns)
    echo "HOST_INSPECT[$fqdn]:  ipa: ERROR: $fqdn: DNS resource record not found" ;;
  hbac_references|sudo_references)
    echo "HOST_INSPECT[$fqdn]: Number of entries returned 0" ;;
  gateway_scope)
    echo "HOST_INSPECT[$fqdn]: GATEWAY_SCOPE_READY=true" ;;
  ssh_retirement)
    b64=$(printf '{"schema_version":1,"kind":"ssh_retirement","fqdn":"%s","alias":"%s","stage":"%s","status":"settled"}' "$fqdn" "$(field pilot_decommission_target_alias)" "$(field pilot_decommission_retirement_stage)" | base64 -w0)
    echo "PILOT_SSH_RETIREMENT_V1:$b64" ;;
  *) echo "unexpected query $q" >&2; exit 3 ;;
  esac ;;
*) echo "unexpected playbook $playbook: $all" >&2; exit 3 ;;
esac
`

const decommissionLockHosts = `hosts:
  client1:
    ansible_host: "10.0.0.9"
    env: sandbox
    roles:
      - freeipa-client
    ipa_client_fqdn: ` + decommissionLockFQDN + `
    freeipa_roster_file: roster.yaml
  ipa-1:
    ansible_host: "192.0.2.10"
    ansible_user: root
    env: sandbox
    roles:
      - freeipa-server
    freeipa_roster_file: roster.yaml
`

const decommissionLockRoster = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
hosts:
  - name: ` + decommissionLockFQDN + `
    state: present
    ip_address: "10.0.0.9"
`

type decommissionLockEnv struct {
	t      *testing.T
	ws     string
	state  string
	events string
	planID string
}

// newDecommissionLockEnv builds the workspace and the fake machines, and plans
// the decommission of client1 with the real planner (so the plan is the one the
// freshness check re-derives): three steps, the uninstall, the roster tombstone
// and the identity converge.
func newDecommissionLockEnv(t *testing.T) *decommissionLockEnv {
	t.Helper()
	for _, tool := range []string{"ansible", "ansible-inventory", "flock", "base64"} {
		mustLookPath(t, tool)
	}
	t.Setenv("ANSIBLE_HOME", t.TempDir())
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	oldData := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = oldData })

	e := &decommissionLockEnv{t: t, ws: t.TempDir(), state: t.TempDir()}
	e.events = filepath.Join(t.TempDir(), "events.log")
	for name, body := range map[string]string{"hosts.yml": decommissionLockHosts, "roster.yaml": decommissionLockRoster} {
		if err := os.WriteFile(filepath.Join(e.ws, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	script := strings.NewReplacer("@STATE@", e.state, "@EVENTS@", e.events).Replace(fakeFreeIPAPlaybook)
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })
	return e
}

// plan runs `pilot host decommission plan` for client1 and checks the plan is
// the three-step one that takes the lock.
func (e *decommissionLockEnv) plan() {
	e.t.Helper()
	out, err := runPilotForTest(e.t, "host", "decommission", "plan", "--dir", e.ws, "--host", "client1")
	if err != nil {
		e.t.Fatalf("plan: %v\n%s", err, out)
	}
	e.planID = extractPlanID(e.t, out)
	plan := e.loadPlan()
	if !planHasIdentityConverge(plan) || plan.Blocked() {
		e.t.Fatalf("the planned decommission is not the executable three-step one: blocked=%v\n%s", plan.Blocked(), out)
	}
}

func (e *decommissionLockEnv) loadPlan() *decommission.Plan {
	e.t.Helper()
	st, err := openSpecStore()
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	plan, err := decommission.NewStore(st).LoadPlan(e.planID)
	if err != nil {
		e.t.Fatal(err)
	}
	return plan
}

func (e *decommissionLockEnv) apply() (string, error) {
	e.t.Helper()
	return runPilotForTest(e.t, "host", "decommission", "apply", "--dir", e.ws, "--id", e.planID, "--confirm-host", "client1")
}

func (e *decommissionLockEnv) resume() (string, error) {
	e.t.Helper()
	return runPilotForTest(e.t, "host", "decommission", "resume", "--dir", e.ws, "--id", e.planID)
}

// applyIn is runHostDecommissionApply itself, for the tests that give it a
// context they cancel.
func (e *decommissionLockEnv) applyIn(ctx context.Context) (*decommission.FinalizeResult, error) {
	e.t.Helper()
	st, err := openSpecStore()
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)
	plan, err := ds.LoadPlan(e.planID)
	if err != nil {
		e.t.Fatal(err)
	}
	catalog, err := loadHostDecommissionCatalog()
	if err != nil {
		e.t.Fatal(err)
	}
	return runHostDecommissionApply(ctx, ds, plan, e.ws, catalog, "apply via a test", noStageAuthorization())
}

// timeline is what changed anything, in order: the fake machines' mutations and
// the lock's own events.
func (e *decommissionLockEnv) timeline() []string { return readEvents(e.t, e.events) }

// untouched asserts that nothing the decommission changes was changed: neither
// machine's mutation ran, the roster entry is not tombstoned and hosts.yml still
// lists the host.
func (e *decommissionLockEnv) untouched() {
	e.t.Helper()
	for _, mutation := range []string{"client uninstall", "identity converge"} {
		if slices.Contains(e.timeline(), mutation) {
			e.t.Fatalf("%q ran: the client, the roster or the server was changed; timeline %v", mutation, e.timeline())
		}
	}
	for _, marker := range []string{"uninstalled", "converged"} {
		if _, err := os.Stat(filepath.Join(e.state, marker)); err == nil {
			e.t.Fatalf("the fake machines are in state %q", marker)
		}
	}
	roster, err := os.ReadFile(filepath.Join(e.ws, "roster.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	if string(roster) != decommissionLockRoster {
		e.t.Fatalf("the roster was changed:\n%s", roster)
	}
	hosts, err := os.ReadFile(filepath.Join(e.ws, "hosts.yml"))
	if err != nil {
		e.t.Fatal(err)
	}
	if string(hosts) != decommissionLockHosts {
		e.t.Fatalf("hosts.yml was changed:\n%s", hosts)
	}
}

// completed asserts the decommission ran to its end: both steps ran, the roster
// entry is a tombstone and the host is gone from hosts.yml.
func (e *decommissionLockEnv) completed(out string, err error) {
	e.t.Helper()
	if err != nil || !strings.Contains(out, "STATUS completed") {
		e.t.Fatalf("the decommission did not complete: %v\n%s", err, out)
	}
	for _, mutation := range []string{"client uninstall", "identity converge"} {
		if !slices.Contains(e.timeline(), mutation) {
			e.t.Fatalf("%q never ran; timeline %v", mutation, e.timeline())
		}
	}
	hosts, readErr := os.ReadFile(filepath.Join(e.ws, "hosts.yml"))
	if readErr != nil {
		e.t.Fatal(readErr)
	}
	if strings.Contains(string(hosts), "client1") {
		e.t.Fatalf("hosts.yml still lists client1:\n%s", hosts)
	}
}

func (e *decommissionLockEnv) fakeLock() *fakeIdentityLock {
	lock := useFakeIdentityLock(e.t)
	lock.Events = func(ev string) { appendEvent(e.t, e.events, ev) }
	return lock
}

// (1) and (5): the lock is taken once, before the uninstall, after the approval,
// and given back after the converge. The converge takes none of its own.
func TestDecommissionApplyTakesTheLockOnceBeforeTheFirstStepAndGivesItBackAfterTheLast(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	if n := len(lock.Requests()) + lock.Acquired(); n != 0 {
		t.Fatalf("plan built or took %d locks: it changes nothing and takes none", n)
	}
	prechecksAfterPlan := len(lock.Prechecks()) // plan's warning asks the precheck, no more

	var atLock struct {
		approved bool
		timeline []string
	}
	lock.OnAcquire = func(context.Context) {
		atLock.approved = planApproved(t, env.planID)
		atLock.timeline = env.timeline()
	}
	out, err := env.apply()
	env.completed(out, err)

	want := []string{"lock ipa-1", "client uninstall", "identity converge", "release ipa-1"}
	if got := env.timeline(); !slices.Equal(got, want) {
		t.Fatalf("timeline = %v, want %v: the lock comes before the first change and goes after the last", got, want)
	}
	if !atLock.approved || !slices.Equal(atLock.timeline, []string{"lock ipa-1"}) {
		t.Fatalf("at the moment the lock was taken: approved %v, timeline %v: want the approval recorded and nothing but the lock itself on the timeline", atLock.approved, atLock.timeline)
	}
	if lock.Acquired() != 1 || lock.Released() != 1 || len(lock.Requests()) != 1 {
		t.Fatalf("acquired %d, released %d, requests %d: want one lock session for the whole run", lock.Acquired(), lock.Released(), len(lock.Requests()))
	}
	if got := len(lock.Prechecks()) - prechecksAfterPlan; got != 1 {
		t.Fatalf("apply asked the precheck %d times, want once, before the approval", got)
	}
	req := onlyRequest(t, lock)
	if req.Inventory != filepath.Join(env.ws, "inventory.yml") || req.Hosts != nil || req.Wait != identityLockWaitDefault || req.Progress == nil || req.Runtime == nil || req.Runtime.TempDir == "" {
		t.Fatalf("request = %+v: want the generated inventory, the freeipa-server group, the default wait, a progress writer and the workspace's Ansible runtime", req)
	}
}

// (2): a lock that is busy fails the run before any step. Nothing changed, the
// approval is kept, and the same plan finishes later, by resume or by apply again,
// without a new plan.
func TestDecommissionApplyWithABusyLockChangesNothingAndTheSamePlanFinishesLater(t *testing.T) {
	busy := &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	for name, again := range map[string]func(e *decommissionLockEnv) (string, error){
		"resume":      (*decommissionLockEnv).resume,
		"apply again": (*decommissionLockEnv).apply,
	} {
		t.Run(name, func(t *testing.T) {
			env := newDecommissionLockEnv(t)
			lock := env.fakeLock()
			env.plan()
			hashBefore := env.loadPlan().PlanHash

			lock.Err = busy
			out, err := env.apply()
			if err == nil || !errors.Is(err, sshdial.ErrLockBusy) {
				t.Fatalf("err = %v, want it to wrap ErrLockBusy\n%s", err, out)
			}
			for _, want := range []string{"was not started", "no step ran", "resume --id " + env.planID} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to hold %q", err, want)
				}
			}
			env.untouched()
			if !planApproved(t, env.planID) {
				t.Fatal("the approval was not kept: resume would refuse and the operator would have to re-plan")
			}
			if got := env.loadPlan(); got.PlanHash != hashBefore || got.Status != decommission.PlanStatusExecutable {
				t.Fatalf("the plan changed (hash %s -> %s, status %s): a busy lock must leave it as it was", hashBefore, got.PlanHash, got.Status)
			}
			if lock.Acquired() != 0 || len(lock.Requests()) != 1 {
				t.Fatalf("acquired %d, requests %d", lock.Acquired(), len(lock.Requests()))
			}

			lock.Err = nil
			env.completed(again(env))
			want := []string{"lock ipa-1", "client uninstall", "identity converge", "release ipa-1"}
			if got := env.timeline(); !slices.Equal(got, want) {
				t.Fatalf("timeline = %v, want %v", got, want)
			}
		})
	}
}

// (3): a context cancelled while the lock is being waited for ends the run before
// any step, and the plan finishes later. The acquirer here blocks until its
// context ends, as the production one does.
func TestDecommissionApplyCancelledWhileWaitingForTheLockChangesNothing(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()

	waiting := make(chan struct{})
	var once sync.Once
	newIdentityLock = func(req identityLockRequest) identitylock.Acquirer {
		return func(ctx context.Context) (*identitylock.Held, error) {
			once.Do(func() { close(waiting) })
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := env.applyIn(ctx)
		done <- err
	}()
	select {
	case <-waiting:
	case <-time.After(30 * time.Second):
		t.Fatal("the run never got to waiting for the lock")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "was not started") {
			t.Fatalf("err = %v, want a refusal that wraps context.Canceled and says the run was not started", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a cancelled wait did not end the run")
	}
	env.untouched()
	if !planApproved(t, env.planID) {
		t.Fatal("the approval was not kept")
	}

	// The plan carries on: the lock is free now.
	newIdentityLock = func(req identityLockRequest) identitylock.Acquirer { return lock.Acquirer() }
	env.completed(env.resume())
}

// The wait that ran out or was interrupted, with the production acquirer over a
// real flock: another run holds the lock, apply waits, its context ends, nothing
// was changed, and once the other run lets go the same plan completes. This is the
// sequence found live (E41), with the lock the production code takes.
func TestDecommissionApplyInterruptedWhileAnotherRunHoldsTheRealLockThenResumes(t *testing.T) {
	env := newDecommissionLockEnv(t)
	seam := useLocalLockDialer(t)
	env.plan()

	holder, err := productionIdentityLock(identityLockRequest{Inventory: filepath.Join(env.ws, "inventory.yml")})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Release() }()
	if !seam.held(t) {
		t.Fatal("the other run does not hold the lock")
	}

	// The run is interrupted 1.5 s after the precheck has finished, that is, while
	// it waits for the lock. A deadline that started with apply would also count
	// the precheck (ansible-inventory, ansible and ansible-config, each of which
	// starts Python): on a slow runner it used up the whole budget before the
	// approval was recorded and the run never reached the wait this test is about.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prevPrecheck := identityLockPrecheck
	t.Cleanup(func() { identityLockPrecheck = prevPrecheck })
	identityLockPrecheck = func(c context.Context, req identityLockRequest) error {
		err := prevPrecheck(c, req)
		time.AfterFunc(1500*time.Millisecond, cancel)
		return err
	}
	started := time.Now()
	_, err = env.applyIn(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the wait to end with the context's cancellation", err)
	}
	if time.Since(started) > 25*time.Second {
		t.Fatalf("the run took %v to give up", time.Since(started))
	}
	env.untouched()
	if !planApproved(t, env.planID) {
		t.Fatal("the approval was not kept")
	}
	if !seam.held(t) {
		t.Fatal("the other run's lock is gone")
	}

	if err := holder.Release(); err != nil {
		t.Fatal(err)
	}
	env.completed(env.resume())
	if seam.held(t) {
		t.Fatal("the lock is still held after the run ended")
	}
	if got, want := env.timeline(), []string{"client uninstall", "identity converge"}; !slices.Equal(got, want) {
		t.Fatalf("timeline = %v, want %v", got, want)
	}
}

// (4): the lock is lost while the uninstall runs. The playbook is killed, the run
// ends with ErrLockLost, and the converge never starts: a run whose lock is gone
// does not go on to the step that needs it.
func TestDecommissionApplyWithTheLockLostDuringTheUninstallStopsBeforeTheConverge(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	if err := os.WriteFile(filepath.Join(env.state, "block-uninstall"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Whatever happens, do not leave the fake playbook waiting after the test.
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(env.state, "release-uninstall"), nil, 0o600) })

	done := make(chan error, 1)
	go func() {
		_, err := env.applyIn(context.Background())
		done <- err
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(env.state, "uninstall-running")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the uninstall never started; timeline %v", env.timeline())
		}
		time.Sleep(20 * time.Millisecond)
	}
	lock.Lose()

	select {
	case err := <-done:
		if !errors.Is(err, identitylock.ErrLockLost) {
			t.Fatalf("err = %v, want it to wrap ErrLockLost", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not end after the lock was lost")
	}
	if got, want := env.timeline(), []string{"lock ipa-1", "client uninstall", "release ipa-1"}; !slices.Equal(got, want) {
		t.Fatalf("timeline = %v, want %v: the converge must not start after the lock is lost", got, want)
	}
	if _, err := os.Stat(filepath.Join(env.state, "converged")); err == nil {
		t.Fatal("the server was converged without the lock")
	}
	if lock.Acquired() != 1 || lock.Released() != 1 {
		t.Fatalf("acquired %d, released %d: a lost lock is still given up by its owner", lock.Acquired(), lock.Released())
	}
}

// (6): a plan that is already completed replays its receipt, takes no lock, runs
// nothing and does not ask whether its inventory can be locked.
func TestDecommissionOfACompletedPlanReplaysItsReceiptWithoutTheLock(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	env.completed(env.apply())
	acquired, requests, prechecks, timeline := lock.Acquired(), len(lock.Requests()), len(lock.Prechecks()), env.timeline()

	for name, run := range map[string]func() (string, error){"apply": env.apply, "resume": env.resume} {
		out, err := run()
		if err != nil || !strings.Contains(out, "STATUS already_completed") {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		if lock.Acquired() != acquired || len(lock.Requests()) != requests || len(lock.Prechecks()) != prechecks {
			t.Fatalf("%s took or asked about the lock again: acquired %d->%d, requests %d->%d, prechecks %d->%d",
				name, acquired, lock.Acquired(), requests, len(lock.Requests()), prechecks, len(lock.Prechecks()))
		}
		if got := env.timeline(); !slices.Equal(got, timeline) {
			t.Fatalf("%s ran something: timeline %v, was %v", name, got, timeline)
		}
	}
}

// (7): a plan without the converge step never runs the identity playbook, so it
// takes no lock and is not asked about one.
func TestDecommissionOfAPlanWithoutTheConvergeStepTakesNoLock(t *testing.T) {
	lock := useFakeIdentityLock(t)
	ws, ansibleLog := writeHostDecommissionStageFixture(t)
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })
	out, err := runPilotForTest(t, "host", "decommission", "plan", "--dir", ws, "--host", "web2")
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	planID := extractPlanID(t, out)
	out, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", planID, "--confirm-host", "web2")
	if err != nil || !strings.Contains(out, "STATUS completed") {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(ansibleLog); statErr != nil {
		t.Fatalf("the plan ran no playbook, so the test proves nothing: %v", statErr)
	}
	if lock.Acquired() != 0 || len(lock.Requests()) != 0 || len(lock.Prechecks()) != 0 {
		t.Fatalf("acquired %d, requests %d, prechecks %d: a plan with no identity converge step must not touch the lock", lock.Acquired(), len(lock.Requests()), len(lock.Prechecks()))
	}
}
