package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
	"github.com/kjelly/pilot/internal/sshdial"
)

// Why the identity lock exists (docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md
// §4, "清除交錯" and "覆蓋交錯"): the authorization cache obligation
// `auth_pending` of the identity playbook's journal is read-modify-written by
// whichever run is last. The Go writer's entry (`auth_prepare`) sets it to
// true before Go writes, and the hybrid run's playbook later settles on what
// its own `auth_prepare` read. Another full run interleaved with it can clear
// it (the obligation is read as "nothing owed") or overwrite it, and the client
// authorization cache is then never refreshed after a revocation.
//
// These tests drive the REAL helper (playbooks/apply/files/freeipa-ssh-key-cache.py,
// run with python3 on a temporary journal) through the exact sequences. The
// first two prove the hazard is real without the lock: the hybrid run settles
// with dirty=false. The third drives the same sequences through two funnels
// (accessgrants.ReconcileOnce and executeDeploymentTransaction) with the real
// lock (the ssh stand-in runs flock on a temporary path) and the fake
// ansible-playbook of each calling the helper: the second funnel waits or fails,
// and the obligation survives to the hybrid run's own settle. The same harness
// with a lock that does not exclude (an in-memory one per funnel) loses it
// again, so the test is what the lock makes the difference to.

const (
	cacheDomain = "ipa.pilot.internal"
	helperRel   = "../../../playbooks/apply/files/freeipa-ssh-key-cache.py"
)

func helperPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(helperRel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	return abs
}

// cacheCall runs one helper action on the journal, as ansible's command module
// does: JSON on stdin, the result on stdout.
func cacheCall(t *testing.T, journal, action string, data map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{"domain": cacheDomain}
	for k, v := range data {
		payload[k] = v
	}
	in, _ := json.Marshal(payload)
	cmd := exec.Command("python3", helperPath(t), action, journal)
	cmd.Stdin = bytes.NewReader(in)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", action, err, out)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("helper %s printed %q: %v", action, out, err)
	}
	return result
}

// ackedBaseline leaves a journal that records no obligation (auth_pending
// false): one full run, prepare, settle, ack.
func ackedBaseline(t *testing.T) string {
	t.Helper()
	journal := filepath.Join(t.TempDir(), "state", "ssh-cache.json")
	prev := cacheCall(t, journal, "auth_prepare", nil)["previous"]
	cacheCall(t, journal, "auth_settle", map[string]any{"previous": prev, "changed": false})
	cacheCall(t, journal, "auth_ack", nil)
	if got := journalPending(t, journal); got {
		t.Fatal("the baseline journal still records an obligation")
	}
	return journal
}

func journalPending(t *testing.T, journal string) bool {
	t.Helper()
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Pending *bool `json:"auth_pending"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil {
		t.Fatal("the journal has no auth_pending")
	}
	return *state.Pending
}

// hybridPlaybook is what the hybrid run's own playbook does, after the entry
// and the Go writes: its own prepare, then settle on what that prepare read
// (nothing else changed: Go's writes are invisible to settle), then the ack
// only if settle says to refresh. It returns the dirty that settle decided.
func hybridPlaybook(t *testing.T, journal string) bool {
	t.Helper()
	prev := cacheCall(t, journal, "auth_prepare", nil)["previous"]
	dirty := cacheCall(t, journal, "auth_settle", map[string]any{"previous": prev, "changed": false})["dirty"].(bool)
	if dirty {
		cacheCall(t, journal, "auth_ack", nil)
	}
	return dirty
}

func fullRun(t *testing.T, journal string) {
	t.Helper()
	prev := cacheCall(t, journal, "auth_prepare", nil)["previous"]
	dirty := cacheCall(t, journal, "auth_settle", map[string]any{"previous": prev, "changed": false})["dirty"].(bool)
	if dirty {
		cacheCall(t, journal, "auth_ack", nil)
	}
}

// 清除交錯: the hybrid run's entry sets the obligation; before Go writes,
// another full run finishes prepare (reads true), settle (dirty), refresh, ack,
// which clears it; the hybrid run's playbook then reads false and settles
// not-dirty: the clients are not refreshed.
func TestAuthCacheClearInterleavingWithoutLockLosesObligation(t *testing.T) {
	journal := ackedBaseline(t)
	cacheCall(t, journal, "auth_prepare", nil) // the hybrid run's entry
	if !journalPending(t, journal) {
		t.Fatal("the entry did not record the obligation")
	}
	fullRun(t, journal) // the other run, entirely inside the hybrid run's window
	if journalPending(t, journal) {
		t.Fatal("the other run did not clear the obligation: the sequence does not reproduce the hazard")
	}
	if dirty := hybridPlaybook(t, journal); dirty {
		t.Fatal("the hybrid run settled dirty: the interleaving did not lose the obligation, so the lock would protect against nothing")
	}
	// The discriminating control: the same two runs one after the other, in
	// either order, keep it.
	for name, hybridFirst := range map[string]bool{"hybrid then full": true, "full then hybrid": false} {
		t.Run(name, func(t *testing.T) {
			journal := ackedBaseline(t)
			if hybridFirst {
				cacheCall(t, journal, "auth_prepare", nil)
				if !hybridPlaybook(t, journal) {
					t.Fatal("serialized, the hybrid run lost its obligation")
				}
				fullRun(t, journal)
			} else {
				fullRun(t, journal)
				cacheCall(t, journal, "auth_prepare", nil)
				if !hybridPlaybook(t, journal) {
					t.Fatal("serialized, the hybrid run lost its obligation")
				}
			}
		})
	}
}

// 覆蓋交錯: another full run's prepare is earlier than the entry (reads false);
// the entry sets the obligation; the full run's settle then overwrites it with
// what its own prepare read (false, nothing changed); the hybrid run's playbook
// reads false.
func TestAuthCacheOverwriteInterleavingWithoutLockLosesObligation(t *testing.T) {
	journal := ackedBaseline(t)
	otherPrev := cacheCall(t, journal, "auth_prepare", nil)["previous"] // the other run's prepare: false
	if otherPrev != false {
		t.Fatalf("the other run's prepare read %v, want false", otherPrev)
	}
	cacheCall(t, journal, "auth_prepare", nil) // the hybrid run's entry (and the Go writes)
	if !journalPending(t, journal) {
		t.Fatal("the entry did not record the obligation")
	}
	cacheCall(t, journal, "auth_settle", map[string]any{"previous": otherPrev, "changed": false}) // the other run's settle
	if journalPending(t, journal) {
		t.Fatal("the other run's settle did not overwrite the obligation: the sequence does not reproduce the hazard")
	}
	if dirty := hybridPlaybook(t, journal); dirty {
		t.Fatal("the hybrid run settled dirty: the interleaving did not lose the obligation")
	}
	t.Run("serialized, the obligation survives", func(t *testing.T) {
		journal := ackedBaseline(t)
		fullRun(t, journal)
		cacheCall(t, journal, "auth_prepare", nil)
		if !hybridPlaybook(t, journal) {
			t.Fatal("serialized, the hybrid run lost its obligation")
		}
	})
}

// ---- the same two sequences through two funnels --------------------------------

// simDriver stands in for ansible-playbook: it is the Python the fake script
// execs, and it calls the real helper through its command line. The runs are:
// "full" (what a legacy full identity run does to the journal: prepare, settle,
// ack when dirty; pausing after prepare when the file <name>.mid.go is wanted)
// and "hybrid" (the entry, a pause for the Go writes, then the playbook's own
// prepare and settle and ack; the dirty it settled on goes to <name>.result).
const simDriver = `
import json, os, subprocess, sys, time
name, helper, journal, d = sys.argv[1:5]
def call(action, data=None):
    payload = {"domain": "ipa.pilot.internal"}
    payload.update(data or {})
    out = subprocess.run(["python3", helper, action, journal], input=json.dumps(payload), capture_output=True, text=True, check=True).stdout
    return json.loads(out)
def log(msg):
    with open(os.path.join(d, "events.log"), "a") as f:
        f.write(name + " " + msg + "\n")
def pause(point):
    open(os.path.join(d, name + "." + point + ".paused"), "w").close()
    log("paused at " + point)
    while not os.path.exists(os.path.join(d, name + "." + point + ".go")):
        time.sleep(0.02)
    log("resumed from " + point)
log("playbook start")
if name.endswith("-full") or name.endswith("-full-mid"):
    prev = call("auth_prepare")["previous"]
    log("prepare read previous=%s" % prev)
    if name.endswith("-mid"):
        pause("mid")
    dirty = call("auth_settle", {"previous": prev, "changed": False})["dirty"]
    log("settle dirty=%s" % dirty)
    if dirty:
        call("auth_ack")
else:
    call("auth_prepare")
    log("entry done")
    pause("window")
    prev = call("auth_prepare")["previous"]
    dirty = call("auth_settle", {"previous": prev, "changed": False})["dirty"]
    log("settle dirty=%s" % dirty)
    open(os.path.join(d, name + ".result"), "w").write(json.dumps({"dirty": dirty}))
    if dirty:
        call("auth_ack")
log("playbook end")
`

type interleaveHarness struct {
	t       *testing.T
	dir     string
	journal string
	inv     string
	roster  string
	seam    *dialerSeam
	helper  string
}

func newInterleaveHarness(t *testing.T) *interleaveHarness {
	t.Helper()
	h := &interleaveHarness{t: t, dir: t.TempDir(), helper: helperPath(t)}
	h.inv = writeLockInventory(t, lockCommonArgs)
	h.seam = useLocalLockDialer(t)
	h.journal = ackedBaseline(t)
	h.roster = writeAccessCLIFixture(t, accessCLIFixtureRoster)
	if err := os.WriteFile(filepath.Join(h.dir, "driver.py"), []byte(simDriver), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// binary is a fake ansible-playbook that runs the simulated run `name`.
func (h *interleaveHarness) binary(name string) string {
	return writeScript(h.t, "ansible-playbook", "#!/bin/sh\nexec python3 '"+filepath.Join(h.dir, "driver.py")+"' '"+name+"' '"+h.helper+"' '"+h.journal+"' '"+h.dir+"'\n")
}

func (h *interleaveHarness) events() []string {
	return readEvents(h.t, filepath.Join(h.dir, "events.log"))
}

func (h *interleaveHarness) exists(name string) bool {
	_, err := os.Stat(filepath.Join(h.dir, name))
	return err == nil
}

func (h *interleaveHarness) release(name string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), nil, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *interleaveHarness) waitFor(file string) {
	h.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if h.exists(file) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("%s never appeared; events: %v", file, h.events())
}

func (h *interleaveHarness) dirtyOfHybrid(name string) bool {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, name+".result"))
	if err != nil {
		h.t.Fatalf("the hybrid run %s never settled: %v; events: %v", name, err, h.events())
	}
	var r struct {
		Dirty bool `json:"dirty"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		h.t.Fatal(err)
	}
	return r.Dirty
}

// lockFor builds the Acquirer of one funnel: the production builder over the
// real (local flock) lock, or, as the control, a lock that excludes nobody.
func (h *interleaveHarness) lockFor(real bool, wait time.Duration, hosts []string) identitylock.Acquirer {
	if !real {
		return (&identitylocktest.Fake{Host: "ipa-1"}).Acquirer()
	}
	return productionIdentityLock(identityLockRequest{Inventory: h.inv, Hosts: hosts, Wait: wait})
}

// accessFunnel runs accessgrants.ReconcileOnce (the funnel behind `pilot access
// reconcile`, breakglass and drift repair) with the simulated run `name`.
func (h *interleaveHarness) accessFunnel(name string, lock identitylock.Acquirer) error {
	runner := ansible.NewRunner()
	runner.Binary = h.binary(name)
	runner.Timeout = 2 * time.Minute
	_, _, err := accessgrants.ReconcileOnce(context.Background(), accessgrants.ReconcileOptions{
		RosterFile: h.roster, Inventory: h.inv, Runner: runner, Lock: lock,
	})
	return err
}

// decommissionFunnel runs the central converge step of a host decommission
// (the funnel behind pilot host decommission) with the simulated run `name`,
// the way runHostDecommissionApply runs it: the owner of the run takes the lock
// first, binds the context of the steps to it and gives it back after the last
// one; the step reads the lock from that context and takes none of its own. (The
// owner itself is driven end to end by host_decommission_lock_test.go.)
func (h *interleaveHarness) decommissionFunnel(name string, lock identitylock.Acquirer) error {
	runner := ansible.NewRunner()
	runner.Binary = h.binary(name)
	runner.Timeout = 2 * time.Minute
	p := providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{
		Executor: runner, InventoryAlias: "web-1", ServerInventory: h.inv,
		IdentityApplyPlaybook: identityPlaybookForTest,
	})
	step, err := p.ExecutorForStep(providers.Step{Action: providers.ActionFreeIPAIdentityApplyConverge,
		TargetIdentity: "web-1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "web-1"}})
	if err != nil {
		return err
	}
	held, err := lock(context.Background())
	if err != nil {
		return err
	}
	defer func() { _ = held.Release() }()
	ctx, cancel := held.Bind(context.Background())
	defer cancel()
	return step.Execute(ctx)
}

// deployFunnel runs executeDeploymentTransaction of the identity playbook
// (the funnel behind pilot deploy and pilot reconcile) with the simulated run.
func (h *interleaveHarness) deployFunnel(name string, lock identitylock.Acquirer) error {
	runner := ansible.NewRunner()
	runner.Binary = h.binary(name)
	runner.Timeout = 2 * time.Minute
	return executeDeploymentTransaction(context.Background(), runner, &bytes.Buffer{}, identityPlaybookForTest, h.inv, "", "", nil, vaultInput{},
		deploymentTransactionOptions{Authorization: &deploymentAuthorization{}, IdentityLock: lock})
}

func (h *interleaveHarness) startFunnel(f func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	return done
}

func (h *interleaveHarness) wait(done <-chan error, what string) error {
	h.t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(60 * time.Second):
		h.t.Fatalf("%s did not end; events: %v", what, h.events())
		return nil
	}
}

func (h *interleaveHarness) before(a, b string) bool {
	h.t.Helper()
	ev := h.events()
	ia, ib := slices.Index(ev, a), slices.Index(ev, b)
	if ia < 0 || ib < 0 {
		h.t.Fatalf("events %q (%d) and %q (%d) are not both in %v", a, ia, b, ib, ev)
	}
	return ia < ib
}

// The clear interleaving through two funnels: the hybrid run (a deploy of the
// identity playbook) is inside its Go write window; a full run through the
// access funnel arrives. With the lock it waits, so the hybrid run's own settle
// still sees the obligation; without one it runs entirely inside the window and
// clears it.
func TestFunnelsSerializeAuthCacheObligation(t *testing.T) {
	// The other full run comes through each of the two funnels that are not the
	// hybrid run's own (the deploy runner): access (pilot access reconcile,
	// breakglass, drift repair) and the decommission converge.
	others := map[string]func(h *interleaveHarness, name string, lock identitylock.Acquirer) error{
		"access":       (*interleaveHarness).accessFunnel,
		"decommission": (*interleaveHarness).decommissionFunnel,
	}
	for otherName, otherFunnel := range others {
		for _, real := range []bool{false, true} {
			name := otherName + "/" + map[bool]string{false: "no lock (control)", true: "real lock"}[real]
			t.Run("clear interleaving/"+name, func(t *testing.T) {
				h := newInterleaveHarness(t)
				hybrid := h.startFunnel(func() error { return h.deployFunnel("H-hybrid", h.lockFor(real, 0, []string{"ipa-1"})) })
				h.waitFor("H-hybrid.window.paused") // the entry is done: auth_pending is true
				if !journalPending(t, h.journal) {
					t.Fatal("the hybrid run's entry left no obligation")
				}
				other := h.startFunnel(func() error { return otherFunnel(h, "O-full", h.lockFor(real, 60*time.Second, nil)) })
				if real {
					time.Sleep(1500 * time.Millisecond) // a fair chance to get in
					if slices.Contains(h.events(), "O-full playbook start") {
						t.Fatal("the second funnel ran its playbook while the first held the lock")
					}
				} else if err := h.wait(other, "the full run"); err != nil {
					t.Fatal(err) // without a lock it runs entirely inside the window
				}
				h.release("H-hybrid.window.go")
				if err := h.wait(hybrid, "the hybrid run"); err != nil {
					t.Fatalf("the hybrid run: %v", err)
				}
				if real {
					if err := h.wait(other, "the full run"); err != nil {
						t.Fatalf("the full run: %v", err)
					}
					if !h.before("H-hybrid playbook end", "O-full playbook start") {
						t.Fatalf("the full run started before the hybrid run ended: %v", h.events())
					}
				}
				if got := h.dirtyOfHybrid("H-hybrid"); got != real {
					t.Fatalf("the hybrid run settled dirty=%v with real lock=%v: want the obligation to survive exactly when the funnels are serialized\n%v", got, real, h.events())
				}
			})
			t.Run("overwrite interleaving/"+name, func(t *testing.T) {
				h := newInterleaveHarness(t)
				other := h.startFunnel(func() error { return otherFunnel(h, "O-full-mid", h.lockFor(real, 60*time.Second, nil)) })
				h.waitFor("O-full-mid.mid.paused") // its prepare has read false
				hybrid := h.startFunnel(func() error { return h.deployFunnel("H-hybrid", h.lockFor(real, 60*time.Second, []string{"ipa-1"})) })
				if real {
					time.Sleep(1500 * time.Millisecond)
					if slices.Contains(h.events(), "H-hybrid playbook start") {
						t.Fatal("the second funnel ran its playbook while the first held the lock")
					}
				} else {
					h.waitFor("H-hybrid.window.paused") // the entry and Go's writes are done, inside the other run
				}
				// The other run settles now and overwrites auth_pending. Only when it
				// has ended does the hybrid run go on to its own playbook: without
				// this order the two would race, and the hazard is the order in which
				// the other run's settle comes first.
				h.release("O-full-mid.mid.go")
				if err := h.wait(other, "the full run"); err != nil {
					t.Fatalf("the full run: %v", err)
				}
				h.release("H-hybrid.window.go")
				if err := h.wait(hybrid, "the hybrid run"); err != nil {
					t.Fatalf("the hybrid run: %v", err)
				}
				if real && !h.before("O-full-mid playbook end", "H-hybrid playbook start") {
					t.Fatalf("the hybrid run started before the full run ended: %v", h.events())
				}
				if got := h.dirtyOfHybrid("H-hybrid"); got != real {
					t.Fatalf("the hybrid run settled dirty=%v with real lock=%v: want the obligation to survive exactly when the funnels are serialized\n%v", got, real, h.events())
				}
			})
		}
	}
}

// The second funnel that cannot wait fails at once and never runs its
// playbook: the obligation is untouched and the first run still settles dirty.
func TestSecondFunnelThatCannotWaitFailsWithoutRunning(t *testing.T) {
	h := newInterleaveHarness(t)
	hybrid := h.startFunnel(func() error { return h.deployFunnel("H-hybrid", h.lockFor(true, 0, []string{"ipa-1"})) })
	h.waitFor("H-hybrid.window.paused")
	err := h.accessFunnel("O-full", h.lockFor(true, 0, nil))
	if !errors.Is(err, sshdial.ErrLockBusy) {
		t.Fatalf("err = %v, want ErrLockBusy", err)
	}
	if slices.Contains(h.events(), "O-full playbook start") {
		t.Fatalf("the playbook ran although the lock was refused: %v", h.events())
	}
	h.release("H-hybrid.window.go")
	if err := h.wait(hybrid, "the hybrid run"); err != nil {
		t.Fatal(err)
	}
	if !h.dirtyOfHybrid("H-hybrid") {
		t.Fatal("the obligation was lost")
	}
}

// Every funnel of the gate is a place the lock could be left out; the same drive
// through a funnel that does not lock is what the PR's mutation run shows
// failing. Here: a funnel whose lock is lost mid-run ends with ErrLockLost.
func TestFunnelEndsWithLockLostWhenTheServerLetsGo(t *testing.T) {
	h := newInterleaveHarness(t)
	held := make(chan *identitylock.Held, 1)
	real := h.lockFor(true, 0, []string{"ipa-1"})
	hybrid := h.startFunnel(func() error {
		return h.deployFunnel("H-hybrid", func(ctx context.Context) (*identitylock.Held, error) {
			got, err := real(ctx)
			if err == nil {
				held <- got
			}
			return got, err
		})
	})
	h.waitFor("H-hybrid.window.paused")
	// The session of the lock ends without Release, as a dropped network does:
	// the dialer behind the held lock is closed under it.
	h.seam.closeLast()
	err := h.wait(hybrid, "the hybrid run")
	if !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", err)
	}
	if (<-held).Active() {
		t.Fatal("a lost lock reads as active")
	}
}
