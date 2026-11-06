package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The production builder of the identity lock (productionIdentityLock): it
// resolves the one FreeIPA server of the inventory with the real `ansible` and
// `ansible-inventory`, derives how to ssh to it with sshdial.TargetFromHostVars,
// and takes /etc/ipa through sshdial.Dialer.AcquireLock. Only the ssh program is
// replaced (a stand-in that runs the remote command locally, flock and all) and
// the lock path (a temporary directory instead of /etc/ipa): everything else is
// the code a funnel runs. An inventory it cannot derive an ssh Target from is
// refused with the variable named, before any ssh starts.

// localFakeSSH is an `ssh` that runs the remote command locally with sh -c, as
// internal/sshdial's tests do, and logs its argv.
func localFakeSSH(t *testing.T) (program, argvLog string) {
	t.Helper()
	dir := t.TempDir()
	argvLog = filepath.Join(dir, "argv.log")
	script := "#!/bin/bash\n( IFS=$'\\t'; printf '%s\\n' \"$*\" ) >> \"" + argvLog + "\"\n" +
		"while [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\nshift 2\nexec sh -c \"$*\"\n"
	program = filepath.Join(dir, "ssh")
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, argvLog
}

// lockDialer is the seam of productionIdentityLock aimed at the fake ssh and a
// lock path in a temporary directory.
type lockDialer struct {
	*sshdial.Dialer
	path string
}

func (d *lockDialer) AcquireLock(ctx context.Context, opts sshdial.LockOptions) (*sshdial.Lock, error) {
	opts.Path = d.path
	return d.Dialer.AcquireLock(ctx, opts)
}

type dialerSeam struct {
	mu      sync.Mutex
	targets []sshdial.Target
	dialers []*lockDialer
	path    string
	ssh     string
}

// useLocalLockDialer replaces newIdentityLockDialer for the test.
func useLocalLockDialer(t *testing.T) *dialerSeam {
	t.Helper()
	ssh, _ := localFakeSSH(t)
	seam := &dialerSeam{path: t.TempDir(), ssh: ssh}
	prev := newIdentityLockDialer
	t.Cleanup(func() { newIdentityLockDialer = prev })
	newIdentityLockDialer = func(target sshdial.Target) identityLockDialer {
		d := &lockDialer{Dialer: &sshdial.Dialer{Target: target, SSH: ssh}, path: seam.path}
		seam.mu.Lock()
		seam.targets = append(seam.targets, target)
		seam.dialers = append(seam.dialers, d)
		seam.mu.Unlock()
		return d
	}
	return seam
}

// closeLast ends the ssh sessions of the last dialer built, the way a dropped
// network ends the session that holds the lock: the lock is lost, not released.
func (s *dialerSeam) closeLast() {
	s.mu.Lock()
	d := s.dialers[len(s.dialers)-1]
	s.mu.Unlock()
	d.Close()
}

func (s *dialerSeam) started() []sshdial.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sshdial.Target(nil), s.targets...)
}

// held reports, with a second flock on the same path, whether somebody holds
// the lock now.
func (s *dialerSeam) held(t *testing.T) bool {
	t.Helper()
	cmd := exec.Command("flock", "--nonblock", "--conflict-exit-code", "75", s.path, "true")
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 75 {
		return true
	}
	if err != nil {
		t.Fatalf("probing the lock: %v", err)
	}
	return false
}

// lockCommonArgs is what a vm-target inventory carries and the success cases
// add to ipa-1.
const lockCommonArgs = "          ansible_ssh_common_args: \"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\"\n"

const lockInventory = `all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
    freeipa-client:
      hosts:
        web-1:
          ansible_host: 192.0.2.20
`

// writeLockInventory writes a real inventory file, with extra lines added to
// ipa-1's variables, and gives ansible a home of its own.
func writeLockInventory(t *testing.T, extraVars string) string {
	t.Helper()
	for _, tool := range []string{"ansible", "ansible-inventory", "flock"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	t.Setenv("ANSIBLE_HOME", t.TempDir())
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	content := lockInventory
	if extraVars != "" {
		content = strings.Replace(content, "          ansible_user: root\n", "          ansible_user: root\n"+extraVars, 1)
	}
	if err := os.WriteFile(inv, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestProductionIdentityLockTakesTheServersLock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hosts []string
	}{
		{"the funnel asks for the freeipa-server group (access, decommission)", nil},
		{"the deploy runner names the hosts it resolved", []string{"ipa-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeLockInventory(t, lockCommonArgs)
			seam := useLocalLockDialer(t)
			held, err := productionIdentityLock(identityLockRequest{Inventory: inv, Hosts: tc.hosts})(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if held.Host != "ipa-1" {
				t.Fatalf("Host = %q: the lock names the inventory name, not the address", held.Host)
			}
			targets := seam.started()
			if len(targets) != 1 {
				t.Fatalf("started %d ssh dialers", len(targets))
			}
			got := targets[0]
			if got.Host != "192.0.2.10" || got.User != "root" || got.Options["StrictHostKeyChecking"] != "no" || got.Options["UserKnownHostsFile"] != "/dev/null" {
				t.Fatalf("target = %+v: not what the inventory says", got)
			}
			if !seam.held(t) || !held.Active() {
				t.Fatal("the lock is not held after the acquirer returned it")
			}
			if err := held.Release(); err != nil {
				t.Fatal(err)
			}
			if seam.held(t) {
				t.Fatal("the lock is still held after Release")
			}
		})
	}
}

// Everything the lock cannot be taken through is refused with the variable
// named, and no ssh starts: the funnel then does not run the playbook, there is
// no "run without the lock" to fall back to (U1).
func TestProductionIdentityLockRefusesWhatItCannotReach(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  string
		wantIn []string
	}{
		{"a docker connection", "          ansible_connection: docker\n", []string{"ansible_connection 是 docker", "只支援 ssh"}},
		{"a local connection", "          ansible_connection: local\n", []string{"ansible_connection 是 local"}},
		{"a connection password", "          ansible_ssh_pass: sentinel-not-a-credential\n", []string{"設定了 ansible_ssh_pass"}},
		{"another connection password", "          ansible_password: sentinel-not-a-credential\n", []string{"設定了 ansible_password"}},
		{"ProxyCommand", "          ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n", []string{"ProxyCommand"}},
		{"an option outside the allowlist", "          ansible_ssh_common_args: \"-o ForwardAgent=yes\"\n", []string{"ForwardAgent"}},
		{"an ssh_args option beyond multiplexing", "          ansible_ssh_args: \"-o ControlMaster=auto -o ForwardAgent=yes\"\n", []string{"ansible_ssh_args 含 ForwardAgent"}},
		{"the ssh executable", "          ansible_ssh_executable: /usr/local/bin/other-ssh\n", []string{"設定了 ansible_ssh_executable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeLockInventory(t, tc.extra)
			seam := useLocalLockDialer(t)
			_, err := productionIdentityLock(identityLockRequest{Inventory: inv})(context.Background())
			if err == nil {
				t.Fatal("the lock was taken on an inventory it cannot describe")
			}
			for _, want := range append([]string{"ipa-1", "freeipa-identity-apply.yml", "不會無鎖執行"}, tc.wantIn...) {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to hold %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "sentinel-not-a-credential") {
				t.Fatalf("the error shows a password: %v", err)
			}
			if got := seam.started(); len(got) != 0 {
				t.Fatalf("an ssh was started for a refused target: %+v", got)
			}
		})
	}
	// The same inventory without the variable is accepted: the refusals above are
	// the variables', not something else's.
	inv := writeLockInventory(t, lockCommonArgs)
	seam := useLocalLockDialer(t)
	held, err := productionIdentityLock(identityLockRequest{Inventory: inv})(context.Background())
	if err != nil {
		t.Fatalf("the unmodified inventory was refused: %v", err)
	}
	_ = held.Release()
	_ = seam
}

func TestProductionIdentityLockNeedsExactlyOneServer(t *testing.T) {
	inv := writeLockInventory(t, "")
	two := strings.Replace(lockInventory, "        ipa-1:", "        ipa-2:\n          ansible_host: 192.0.2.11\n        ipa-1:", 1)
	if err := os.WriteFile(inv, []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	seam := useLocalLockDialer(t)
	for _, req := range []identityLockRequest{
		{Inventory: inv}, // the group has two
		{Inventory: inv, Hosts: []string{"ipa-1", "ipa-2"}}, // the deploy runner resolved two
		{Inventory: inv, Hosts: []string{}},                 // none: refused, not "look again"
	} {
		_, err := productionIdentityLock(req)(context.Background())
		if err == nil || !strings.Contains(err.Error(), "剛好一台 freeipa-server") {
			t.Fatalf("hosts %v: err = %v, want the exactly-one refusal", req.Hosts, err)
		}
	}
	if got := seam.started(); len(got) != 0 {
		t.Fatalf("an ssh was started: %+v", got)
	}
}

// Busy: the second take fails with the sentinel, names the server and the
// path, and does not wait when told not to; waiting prints a line now and then.
func TestProductionIdentityLockBusyAndWaiting(t *testing.T) {
	inv := writeLockInventory(t, "")
	seam := useLocalLockDialer(t)
	first, err := productionIdentityLock(identityLockRequest{Inventory: inv})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()

	t.Run("wait 0 fails at once, silently", func(t *testing.T) {
		var progress bytes.Buffer
		started := time.Now()
		_, err := productionIdentityLock(identityLockRequest{Inventory: inv, Wait: 0, Progress: &progress})(context.Background())
		if !errors.Is(err, sshdial.ErrLockBusy) {
			t.Fatalf("err = %v, want ErrLockBusy", err)
		}
		for _, want := range []string{"ipa-1", sshdial.DefaultLockPath} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want it to name %q", err, want)
			}
		}
		if progress.Len() != 0 || time.Since(started) > 20*time.Second {
			t.Fatalf("progress %q after %v: wait 0 must not wait or announce", progress.String(), time.Since(started))
		}
	})
	t.Run("a wait prints progress and ends in busy", func(t *testing.T) {
		prev := identityLockProgressEvery
		identityLockProgressEvery = 100 * time.Millisecond
		t.Cleanup(func() { identityLockProgressEvery = prev })
		var progress syncBuffer
		_, err := productionIdentityLock(identityLockRequest{Inventory: inv, Wait: time.Second, Progress: &progress})(context.Background())
		if !errors.Is(err, sshdial.ErrLockBusy) {
			t.Fatalf("err = %v, want ErrLockBusy after the wait", err)
		}
		if out := progress.String(); !strings.Contains(out, "等待 FreeIPA server ipa-1") || !strings.Contains(out, "上限 1s") {
			t.Fatalf("progress = %q, want lines naming the server and the limit", out)
		}
	})
	t.Run("a waiter gets the lock when the holder releases", func(t *testing.T) {
		got := make(chan error, 1)
		go func() {
			held, err := productionIdentityLock(identityLockRequest{Inventory: inv, Wait: 30 * time.Second})(context.Background())
			if err == nil {
				err = held.Release()
			}
			got <- err
		}()
		time.Sleep(500 * time.Millisecond)
		select {
		case err := <-got:
			t.Fatalf("the waiter got the lock while it was held: %v", err)
		default:
		}
		if err := first.Release(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-got:
			if err != nil {
				t.Fatalf("the waiter: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the waiter never got the lock")
		}
	})
	_ = seam
}

// Cancelling while waiting leaves nothing behind locally.
func TestProductionIdentityLockStopsWaitingWhenCancelled(t *testing.T) {
	inv := writeLockInventory(t, "")
	useLocalLockDialer(t)
	first, err := productionIdentityLock(identityLockRequest{Inventory: inv})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := productionIdentityLock(identityLockRequest{Inventory: inv, Wait: 30 * time.Second})(ctx)
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want it to wrap context.Canceled", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a cancelled wait did not end")
	}
}

// The TUI funnel does not wait and says where to go instead.
func TestTUIIdentityLockDoesNotWaitAndPointsAtTheCommandThatDoes(t *testing.T) {
	var got []identityLockRequest
	prev := newIdentityLock
	t.Cleanup(func() { newIdentityLock = prev })
	newIdentityLock = func(req identityLockRequest) identitylock.Acquirer {
		got = append(got, req)
		return func(context.Context) (*identitylock.Held, error) {
			return nil, fmt.Errorf("busy: %w", sshdial.ErrLockBusy)
		}
	}
	_, err := tuiIdentityLock("/ws/inventory.yml")(context.Background())
	if len(got) != 1 || got[0].Wait != 0 || got[0].Inventory != "/ws/inventory.yml" || got[0].Progress != nil {
		t.Fatalf("request = %+v: the TUI must not wait and has nowhere to show progress", got)
	}
	if !errors.Is(err, sshdial.ErrLockBusy) || !strings.Contains(err.Error(), "pilot access breakglass activate") {
		t.Fatalf("err = %v, want ErrLockBusy and the command that waits", err)
	}
	// Another failure is not dressed up as busy.
	newIdentityLock = func(identityLockRequest) identitylock.Acquirer {
		return func(context.Context) (*identitylock.Held, error) { return nil, errors.New("ssh: no route") }
	}
	_, err = tuiIdentityLock("/ws/inventory.yml")(context.Background())
	if err == nil || strings.Contains(err.Error(), "pilot access breakglass") {
		t.Fatalf("err = %v", err)
	}
}
