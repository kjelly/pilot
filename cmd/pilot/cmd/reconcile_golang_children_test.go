package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/childproc"
	"github.com/kjelly/pilot/internal/sshdial"
)

// Spec §2.5: every child process of the Go preview ends, with the processes it
// started, when the preview's context ends (--timeout, Ctrl-C, SIGTERM,
// SIGHUP), and none can hold the preview past WaitDelay by keeping a pipe open.
// ansible-core runs the vault password client script for every one of
// ansible-inventory, ansible and ansible-vault and lets it inherit stderr, an
// ssh ProxyJump hop does the same: a fake tool here stands for either by
// starting a helper that holds only stderr. Each row names the gate it makes
// fire and asserts the same things: exit 1, the context error (or the
// held-pipe error), a bound on the elapsed time that a hang cannot meet, the
// recorded child and helper pids gone (looked up, not slept for), no plan, no
// secret anywhere, and nothing sent to FreeIPA that the step allows.

const (
	// childPIDsEnv names the directory the fake tools of a row record the pids
	// of what they start in. The outer test makes it, so that it can kill what
	// a failing row leaves even when the row's own process had to be killed.
	childPIDsEnv = "PILOT_TEST_CHILDREN_PIDS"
	// childExeEnv is this test binary, which a fake ssh runs as the tunnel's
	// far end.
	childExeEnv = "PILOT_TEST_EXE"
	// childRelayEnv, set to host:port, makes this test binary a relay between
	// its stdin and stdout and that address, and nothing else.
	childRelayEnv = "PILOT_TEST_CHILD_RELAY"
)

// A fake ssh -W runs this test binary as its relay. It must be the process
// that ssh would be (no wrapper, no test framework output on stdout), so it
// acts before the testing package starts anything.
func init() {
	if addr := os.Getenv(childRelayEnv); addr != "" {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "relay:", err)
			os.Exit(255)
		}
		go func() { _, _ = io.Copy(conn, os.Stdin); _ = conn.Close() }()
		_, _ = io.Copy(os.Stdout, conn)
		os.Exit(0)
	}
}

// recordPID is the shell for writing value to the file "pid.<name>" of pids,
// atomically. name may hold shell variables ($$, $!).
func recordPID(pids, name, value string) string {
	f := filepath.Join(pids, "pid."+name)
	return "echo " + value + " > \"" + f + ".tmp\" && mv \"" + f + ".tmp\" \"" + f + "\"\n"
}

// holder is the shell that starts a helper holding only stderr (as a vault
// password client script does), in the tool's process group or, escaped, in a
// session of its own, and records its pid.
func holder(pids string, escaped bool) string {
	sleeper := "sleep 300"
	if escaped {
		sleeper = "setsid sleep 300"
	}
	return sleeper + " >/dev/null </dev/null &\n" + recordPID(pids, "helper.$!", "$!")
}

// stall records the tool's own pid under name and becomes a process that never
// ends.
func stall(pids, name string) string {
	return recordPID(pids, name, "$$") + "exec sleep 300\n"
}

func childAlive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// recordedPIDs returns the pids of the files pid.<glob> of dir.
func recordedPIDs(t *testing.T, dir, glob string) []int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "pid."+glob))
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, f := range files {
		if strings.HasSuffix(f, ".tmp") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			t.Fatalf("%s: %q", f, data)
		}
		pids = append(pids, pid)
	}
	return pids
}

// killRecorded kills every process any fake tool recorded.
func killRecorded(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "pid.*"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
}

// assertGone fails unless the pid files matching glob exist and name only
// processes that are gone within a second.
func assertGone(t *testing.T, dir, glob string) {
	t.Helper()
	pids := recordedPIDs(t, dir, glob)
	if len(pids) == 0 {
		t.Fatalf("no pid.%s was recorded: the fake tool never got to that point, so the row proves nothing", glob)
	}
	for _, pid := range pids {
		for deadline := time.Now().Add(time.Second); childAlive(pid); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("pid.%s: process %d is still running after the preview returned", glob, pid)
			}
		}
	}
}

func assertSurvives(t *testing.T, dir, glob string) {
	t.Helper()
	pids := recordedPIDs(t, dir, glob)
	if len(pids) == 0 {
		t.Fatalf("no pid.%s was recorded", glob)
	}
	// A SIGKILL takes a moment to show: a process that is meant to be left
	// alone must stay for half a second, not for the instant it is looked at.
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, pid := range pids {
			if !childAlive(pid) {
				t.Fatalf("pid.%s: process %d is gone, but nothing can reach a process that left the group (or a reaped child's group)", glob, pid)
			}
		}
	}
}

// childWorld is what a row's setup works with.
type childWorld struct {
	t    *testing.T
	pids string
	f    *fakeIPA
}

func (w *childWorld) sshLog() string { return filepath.Join(w.pids, "ssh.log") }

// tunnel is the shell of a -W call that works: it records its pid and becomes
// a relay (this test binary, see init) to the fake FreeIPA.
func (w *childWorld) tunnel() string {
	return recordPID(w.pids, "tunnel.$$", "$$") +
		"export " + childRelayEnv + "='" + w.f.srv.Listener.Addr().String() + "'\nexec \"$" + childExeEnv + "\"\n"
}

// frozenTunnel is the shell of -W calls whose from-th (1-based) and later
// calls take the ClientHello into their stdin and never answer, as ssh -W does
// in front of a SIGSTOPped httpd: the TLS handshake never completes, so the
// dial that net/http runs in a goroutine of its own never does. Earlier calls
// are working tunnels. Each frozen call records its pid as tunnel.<pid>.
func (w *childWorld) frozenTunnel(from int) string {
	count := filepath.Join(w.pids, "tunnels")
	return "n=$(cat '" + count + "' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '" + count + "'\n" +
		"if [ \"$n\" -ge " + strconv.Itoa(from) + " ]; then\n" +
		recordPID(w.pids, "tunnel.$$", "$$") + "exec sleep 300\nfi\n" + w.tunnel()
}

// sshHooks are the shell of what the fake ssh does for each kind of call; an
// empty hook is the working behaviour. A hook ends the call (exit or exec),
// or falls through to exit 0.
type sshHooks struct{ fqdn, ca, tunnel string }

// fakeSSH puts an ssh on PATH that answers like the FreeIPA server's: the
// FQDN, the CA, and a -W tunnel that is a relay to the fake FreeIPA (this test
// binary, see init). Every call is logged and records `/proc/<pid>/stat`.
func (w *childWorld) fakeSSH(h sshHooks) {
	t := w.t
	t.Helper()
	caFile := filepath.Join(w.pids, "ca.crt")
	if err := os.WriteFile(caFile, w.f.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if h.fqdn == "" {
		h.fqdn = "echo " + golangTestFQDN + "\n"
	}
	if h.ca == "" {
		h.ca = "cat '" + caFile + "'\n"
	}
	if h.tunnel == "" {
		h.tunnel = w.tunnel()
	}
	body := "echo \"$*\" >> '" + w.sshLog() + "'\n" +
		"cat /proc/$$/stat > \"" + filepath.Join(w.pids, "stat.ssh.") + "$$\"\n" +
		"case \"$*\" in\n" +
		"*\" -W \"*)\n" + h.tunnel + "exit 0\n;;\n" +
		"*\"hostname -f\"*)\n" + h.fqdn + "exit 0\n;;\n" +
		"*\"cat /etc/ipa/ca.crt\"*)\n" + h.ca + "exit 0\n;;\n" +
		"esac\nexit 99\n"
	fakeTool(t, "ssh", body)
}

// lateCloseDialer is the real dialer whose connections close after a delay.
type lateCloseDialer struct {
	*sshdial.Dialer
	delay time.Duration
}

func (d *lateCloseDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &lateCloseConn{Conn: c, delay: d.delay}, nil
}

type lateCloseConn struct {
	net.Conn
	delay time.Duration
}

func (c *lateCloseConn) Close() error {
	time.Sleep(c.delay)
	return c.Conn.Close()
}

// childRow is one child process stalling (or misbehaving) and what the preview
// must do about it.
type childRow struct {
	name string
	gate string
	// timeout is --timeout; limit, when set, is --limit.
	timeout, limit string
	// realDialer runs the real sshdial.Dialer against a fake ssh on PATH, as
	// the operator's pilot does; otherwise the dialer is the in-process fake.
	realDialer bool
	// lateClose, with realDialer, makes closing a tunnel connection take this
	// long before ssh is killed: the end of a connection that net/http leaves
	// to a goroutine of its own then comes after the preview returned, which
	// is what pilot's os.Exit does to it. Without the delay that goroutine and
	// the return race, and a row about it sometimes passes on code that has
	// the defect (C13 2 runs in 8, C14 1 in 8, when measured).
	lateClose time.Duration
	setup     func(t *testing.T, w *childWorld)
	// signal, when set, is sent to the process once pid.<signalAt> exists, and
	// the elapsed time is measured from then.
	signal   syscall.Signal
	signalAt string

	wantErr, notErr []error
	want, notWant   []string
	// minElapsed is a lower bound on the run (a wait that must have happened).
	minElapsed time.Duration
	// extra is time the row's own steps take after the deadline (a logout).
	extra time.Duration
	// gone and survive are pid file globs: the processes must be gone, or
	// still be there.
	gone, survive []string
	// calls are the Ansible tools run, in order (toolCalls).
	calls []string
	// sshCalls is how many times ssh ran (realDialer rows).
	sshCalls int
	// methods are the JSON-RPC methods the server saw; nil: no login at all.
	methods []string
}

func inventoryJSON() string {
	return `{"_meta":{"hostvars":{"ipa-1":{"freeipa_roster_file":".vault/ipa-identity.yaml","ansible_host":"192.0.2.10","ansible_user":"root"}}},"freeipa-server":{"hosts":["ipa-1"]}}`
}

func needSetsid(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skipf("setsid not installed: %v", err)
	}
}

// signalIgnoredAtStart reports whether this process started with sig ignored
// (nohup, a background job of a non-interactive shell), as the kernel shows it.
func signalIgnoredAtStart(sig syscall.Signal) bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if mask, ok := strings.CutPrefix(line, "SigIgn:"); ok {
			v, err := strconv.ParseUint(strings.TrimSpace(mask), 16, 64)
			return err == nil && v&(1<<(uint(sig)-1)) != 0
		}
	}
	return false
}

func childRows() []childRow {
	stallsWithHelper := func(tool string, escaped bool) func(*testing.T, *childWorld) {
		return func(t *testing.T, w *childWorld) {
			fakeTool(t, tool, holder(w.pids, escaped)+stall(w.pids, "child"))
		}
	}
	deadline := []error{context.DeadlineExceeded}
	const lateClose = 500 * time.Millisecond
	// The Ansible tools the preview has run by the time it reads over ssh.
	inventoryAndHosts := []string{"ansible-inventory", "ansible"}
	var rows []childRow
	rows = append(rows,
		childRow{
			name: "C1_ansible-inventory_stalls_at_the_deadline_with_a_helper",
			gate: "ansible-inventory", timeout: "4s", setup: stallsWithHelper("ansible-inventory", false),
			wantErr: deadline, want: []string{"ansible-inventory --list"}, gone: []string{"child", "helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			name: "C6_ansible_--list-hosts_stalls_at_the_deadline_with_a_helper",
			gate: "list-hosts", timeout: "4s", setup: stallsWithHelper("ansible", false),
			wantErr: deadline, want: []string{"--list-hosts"}, gone: []string{"child", "helper.*"}, calls: []string{"ansible-inventory", "ansible"},
		},
	)
	rows = append(rows,
		childRow{
			name: "C2_ctrl-c_ends_a_stalled_ansible-inventory_and_its_helper",
			gate: "ansible-inventory", timeout: "10m", setup: stallsWithHelper("ansible-inventory", false),
			signal: syscall.SIGINT, signalAt: "child",
			wantErr: []error{context.Canceled}, notErr: deadline, want: []string{"ansible-inventory --list"},
			gone: []string{"child", "helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			name: "C3_a_hangup_ends_a_stalled_ansible-inventory_and_its_helper",
			gate: "ansible-inventory", timeout: "10m", setup: stallsWithHelper("ansible-inventory", false),
			signal: syscall.SIGHUP, signalAt: "child",
			wantErr: []error{context.Canceled}, notErr: deadline, want: []string{"ansible-inventory --list"},
			gone: []string{"child", "helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			// A helper that left the process group cannot be killed, and holds
			// stderr: the wait for it is what the delay bounds.
			name: "C4_an_escaped_helper_does_not_hold_the_deadline",
			gate: "ansible-inventory", timeout: "4s", setup: stallsWithHelper("ansible-inventory", true),
			wantErr: deadline, want: []string{"ansible-inventory --list"}, minElapsed: 4 * time.Second,
			gone: []string{"child"}, survive: []string{"helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			// Exit 0 with a helper still holding the pipe: the output may be
			// partial, so the step fails and the (valid) inventory is not used.
			name: "C5_ansible-inventory_exits_0_but_a_helper_keeps_the_output",
			gate: "ansible-inventory", timeout: "2m",
			setup: func(t *testing.T, w *childWorld) {
				fakeTool(t, "ansible-inventory", holder(w.pids, false)+"cat <<'EOF'\n"+inventoryJSON()+"\nEOF\nexit 0")
			},
			wantErr: []error{childproc.ErrHelperKeptOutput, exec.ErrWaitDelay}, notErr: []error{context.DeadlineExceeded, context.Canceled},
			want: []string{"ansible-inventory --list", "kept its output open"}, minElapsed: 1500 * time.Millisecond,
			survive: []string{"helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			// ansible's own "no hosts" message, printed before the stall, must
			// not turn the killed run into zero hosts (and the exactly-one
			// refusal): the deadline is what ended it.
			name: "C7_a_deadline_is_not_zero_hosts",
			gate: "list-hosts", timeout: "4s", limit: "ipa-1",
			setup: func(t *testing.T, w *childWorld) {
				fakeTool(t, "ansible", "echo '[ERROR]: Specified inventory, host pattern and/or --limit leaves us with no hosts to target.' >&2\n"+stall(w.pids, "child"))
			},
			wantErr: deadline, want: []string{"--list-hosts"}, notWant: []string{"剛好一台", "有 0 台"},
			gone: []string{"child"}, calls: []string{"ansible-inventory", "ansible"},
		},
		childRow{
			name: "C8_ssh_stalls_reading_the_fqdn_with_a_helper",
			gate: "fqdn-read", timeout: "4s", realDialer: true,
			setup: func(t *testing.T, w *childWorld) {
				w.fakeSSH(sshHooks{fqdn: holder(w.pids, false) + stall(w.pids, "ssh")})
			},
			wantErr: deadline, want: []string{"讀取 ipa-1 的 FQDN", "hostname -f"}, gone: []string{"ssh", "helper.*"}, sshCalls: 1, calls: inventoryAndHosts,
		},
		childRow{
			name: "C9_ssh_prints_the_fqdn_and_exits_0_but_a_helper_keeps_the_output",
			gate: "fqdn-read", timeout: "2m", realDialer: true,
			setup: func(t *testing.T, w *childWorld) {
				w.fakeSSH(sshHooks{fqdn: holder(w.pids, false) + "echo " + golangTestFQDN + "\nexit 0\n"})
			},
			wantErr: []error{childproc.ErrHelperKeptOutput, exec.ErrWaitDelay}, notErr: []error{context.DeadlineExceeded, context.Canceled},
			want: []string{"讀取 ipa-1 的 FQDN", "kept its output open"}, minElapsed: 1500 * time.Millisecond,
			survive: []string{"helper.*"}, sshCalls: 1, calls: inventoryAndHosts,
		},
		childRow{
			name: "C10_ssh_stalls_reading_the_ca_with_a_helper",
			gate: "ca-read", timeout: "4s", realDialer: true,
			setup: func(t *testing.T, w *childWorld) {
				w.fakeSSH(sshHooks{ca: holder(w.pids, false) + stall(w.pids, "ssh")})
			},
			wantErr: deadline, want: []string{"讀取 ipa-1 的 IPA CA", "cat /etc/ipa/ca.crt"}, gone: []string{"ssh", "helper.*"}, sshCalls: 2, calls: inventoryAndHosts,
		},
		childRow{
			// The server never answers the ping or the logout: the tunnel's
			// ssh and the helper in its group are killed when the request is
			// cancelled, and the logout's fresh tunnel is killed at its own
			// bound.
			name: "C11_frozen_server_leaves_no_tunnel_and_no_helper",
			gate: "check-server", timeout: "4s", realDialer: true, extra: time.Second,
			setup: func(t *testing.T, w *childWorld) {
				w.f.hang = map[string]bool{"ping": true, "session_logout": true}
				shortLogout(t)
				w.fakeSSH(sshHooks{tunnel: holder(w.pids, false) + w.tunnel()})
			},
			wantErr: deadline, want: []string{"context deadline exceeded"}, gone: []string{"tunnel.*", "helper.*"},
			methods: []string{"ping", "session_logout"}, calls: inventoryAndHosts,
		},
		childRow{
			// SIGTERM, which the service manager sends, ends the preview like
			// Ctrl-C does.
			name: "C2b_sigterm_ends_a_stalled_ansible-inventory_and_its_helper",
			gate: "ansible-inventory", timeout: "10m", setup: stallsWithHelper("ansible-inventory", false),
			signal: syscall.SIGTERM, signalAt: "child",
			wantErr: []error{context.Canceled}, notErr: deadline, want: []string{"ansible-inventory --list"},
			gone: []string{"child", "helper.*"}, calls: []string{"ansible-inventory"},
		},
		childRow{
			// The ping hangs and the deadline cancels it; the logout dials a
			// fresh tunnel that works and is answered. The tunnel is closed
			// with the client, before the preview returns.
			name: "C15_a_logout_that_is_answered_leaves_no_tunnel",
			gate: "check-server", timeout: "4s", realDialer: true,
			setup: func(t *testing.T, w *childWorld) {
				w.f.hang = map[string]bool{"ping": true}
				w.fakeSSH(sshHooks{})
			},
			wantErr: deadline, want: []string{"context deadline exceeded"}, gone: []string{"tunnel.*"},
			methods: []string{"ping", "session_logout"}, calls: inventoryAndHosts, sshCalls: 4,
		},
		childRow{
			// The ping hangs and the deadline cancels it; the logout dials a
			// fresh tunnel whose TLS handshake never completes (httpd stopped),
			// so when the logout gives up that dial is still running in
			// net/http's goroutine, which ends its connection only after
			// CloseIdleConnections returned. The ssh must be reaped when the
			// preview returns, not later by that goroutine (or never, once
			// pilot exits).
			name: "C13_a_logout_handshake_that_never_completes_leaves_no_tunnel",
			gate: "check-server", timeout: "4s", realDialer: true, lateClose: lateClose, extra: time.Second,
			setup: func(t *testing.T, w *childWorld) {
				w.f.hang = map[string]bool{"ping": true}
				shortLogout(t)
				w.fakeSSH(sshHooks{tunnel: w.frozenTunnel(2)})
			},
			wantErr: deadline, want: []string{"context deadline exceeded"}, gone: []string{"tunnel.*"},
			methods: []string{"ping"}, calls: inventoryAndHosts, sshCalls: 4,
		},
		childRow{
			// The same with Ctrl-C once the server has the ping (live arm L2:
			// httpd stopped after the login, one Ctrl-C).
			name: "C13b_ctrl-c_then_a_logout_handshake_that_never_completes",
			gate: "check-server", timeout: "10m", realDialer: true, lateClose: lateClose, extra: time.Second + lateClose,
			signal: syscall.SIGINT, signalAt: "pinged",
			setup: func(t *testing.T, w *childWorld) {
				w.f.hang = map[string]bool{"ping": true}
				// pid.pinged names the first tunnel (an ssh already gone by the
				// time it matters): the file only says the server has the ping.
				w.f.onHang = func(string) {
					if tunnels, _ := filepath.Glob(filepath.Join(w.pids, "pid.tunnel.*")); len(tunnels) > 0 {
						if data, err := os.ReadFile(tunnels[0]); err == nil {
							_ = os.WriteFile(filepath.Join(w.pids, "pid.pinged"), data, 0o600)
						}
					}
				}
				shortLogout(t)
				w.fakeSSH(sshHooks{tunnel: w.frozenTunnel(2)})
			},
			wantErr: []error{context.Canceled}, notErr: deadline, want: []string{"interrupt signal received"}, gone: []string{"tunnel.*"},
			methods: []string{"ping"}, calls: inventoryAndHosts, sshCalls: 4,
		},
		childRow{
			// The login's own handshake never completes: the deadline ends the
			// login while net/http still dials.
			name: "C14_a_login_handshake_that_never_completes_leaves_no_tunnel",
			gate: "login", timeout: "4s", realDialer: true, lateClose: lateClose,
			setup: func(t *testing.T, w *childWorld) {
				w.fakeSSH(sshHooks{tunnel: w.frozenTunnel(1)})
			},
			wantErr: deadline, want: []string{"登入 FreeIPA", "context deadline exceeded"}, gone: []string{"tunnel.*"},
			calls: inventoryAndHosts, sshCalls: 3,
		},
	)
	return rows
}

// shortLogout bounds the logout after the deadline to a second for the test.
func shortLogout(t *testing.T) {
	t.Helper()
	prev := golangLogoutTimeout
	golangLogoutTimeout = time.Second
	t.Cleanup(func() { golangLogoutTimeout = prev })
}

// unreapedAtReturn lists, now that the preview has returned, the recorded
// processes of the globs that are direct children of the preview and still
// have a /proc entry (a zombie too: Wait has not returned for them). Helpers
// are grandchildren, nobody waits for them. There is no grace: a child the
// preview leaves to another goroutine to end is still there at this moment,
// and in pilot, which exits right after the preview returns, it stays.
func unreapedAtReturn(t *testing.T, pids string, globs []string) []string {
	t.Helper()
	var left []string
	for _, glob := range globs {
		if strings.HasPrefix(glob, "helper") {
			continue
		}
		for _, pid := range recordedPIDs(t, pids, glob) {
			if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
				left = append(left, glob+"="+strconv.Itoa(pid))
			}
		}
	}
	return left
}

// A fake tool stalls and starts a helper that keeps the output open: each row
// is one way a child can hold the preview, and what ends it.
func TestReconcileGolangChildProcesses(t *testing.T) {
	for _, row := range childRows() {
		t.Run(row.name, func(t *testing.T) {
			t.Logf("gate: %s", row.gate)
			if strings.Contains(row.name, "escaped") {
				needSetsid(t)
			}
			if row.signal == syscall.SIGHUP && signalIgnoredAtStart(syscall.SIGHUP) {
				t.Skip("SIGHUP is ignored in this process (nohup): the preview leaves an ignored hangup alone, see the next test")
			}
			pids := os.Getenv(childPIDsEnv)
			if os.Getenv(isolatedCaseEnv) != t.Name() {
				// The outer process makes the directory and kills what a row
				// leaves, also when the row's own process had to be killed.
				pids = t.TempDir()
				t.Setenv(childPIDsEnv, pids)
				t.Cleanup(func() { killRecorded(pids) })
			}
			runIsolated(t, 90*time.Second, func(t *testing.T) { runChildRow(t, row, pids) })
		})
	}
}

func runChildRow(t *testing.T, row childRow, pids string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(childExeEnv, exe)
	f := newFakeIPA(t, "p1-self")
	var targets *[]sshdial.Target
	if !row.realDialer {
		targets = withFakeDialer(t, f)
	} else if row.lateClose > 0 {
		prev := newGolangDialer
		newGolangDialer = func(target sshdial.Target) golangDialer {
			return &lateCloseDialer{Dialer: &sshdial.Dialer{Target: target}, delay: row.lateClose}
		}
		t.Cleanup(func() { newGolangDialer = prev })
	}
	dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	row.setup(t, &childWorld{t: t, pids: pids, f: f})
	calls := toolCalls(t)
	plan := filepath.Join(dir, "plan.json")
	args := previewArgs("--timeout", row.timeout, "--plan-out", plan)
	if row.limit != "" {
		args = append(args, "--limit", row.limit)
	}

	var out string
	var runErr error
	var elapsed time.Duration
	if row.signal == 0 {
		begin := time.Now()
		out, runErr = runReconcileCLI(t, args...)
		elapsed = time.Since(begin)
	} else {
		out, elapsed, runErr = runPreviewAndSignal(t, args, row.signal, filepath.Join(pids, "pid."+row.signalAt))
	}
	unreaped := unreapedAtReturn(t, pids, row.gone)

	// Exit 1, the sentinel, the step.
	if runErr == nil {
		t.Fatalf("the preview went through\n%s", out)
	}
	if processExitCode(runErr) != 1 {
		t.Fatalf("exit %d, want 1: %v", processExitCode(runErr), runErr)
	}
	for _, want := range row.wantErr {
		if !errors.Is(runErr, want) {
			t.Fatalf("err = %v, want it to wrap %v", runErr, want)
		}
	}
	for _, not := range row.notErr {
		if errors.Is(runErr, not) {
			t.Fatalf("err = %v wraps %v", runErr, not)
		}
	}
	for _, want := range row.want {
		if !strings.Contains(runErr.Error(), want) {
			t.Fatalf("err = %v, want it to hold %q", runErr, want)
		}
	}
	for _, not := range row.notWant {
		if strings.Contains(runErr.Error(), not) {
			t.Fatalf("err = %v holds %q", runErr, not)
		}
	}

	// The time: a hang is the failure these rows exist for, and it outlasts
	// any bound by minutes (the helpers sleep 300s). A row that ends at its
	// deadline may take that long, plus the wait delay and what it does after.
	budget := row.extra + childproc.WaitDelay + 10*time.Second
	if slices.Contains(row.wantErr, context.DeadlineExceeded) {
		timeout, err := time.ParseDuration(row.timeout)
		if err != nil {
			t.Fatal(err)
		}
		budget += timeout
	}
	if elapsed > budget {
		t.Fatalf("returned after %s, want within %s", elapsed, budget)
	}
	if elapsed < row.minElapsed {
		t.Fatalf("returned after %s, want at least %s: the wait it is about did not happen", elapsed, row.minElapsed)
	}

	// No leftover process, except the ones that cannot be reached. A direct
	// child is reaped when the preview returns, not after a grace.
	if len(unreaped) != 0 {
		t.Fatalf("still running or unreaped when the preview returned: %v", unreaped)
	}
	for _, glob := range row.gone {
		assertGone(t, pids, glob)
	}
	for _, glob := range row.survive {
		assertSurvives(t, pids, glob)
	}

	// Nothing later ran.
	if got := calls(); !slices.Equal(got, row.calls) {
		t.Fatalf("Ansible tools run = %v, want %v", got, row.calls)
	}
	if row.sshCalls > 0 {
		data, _ := os.ReadFile(filepath.Join(pids, "ssh.log"))
		if n := strings.Count(string(data), "\n"); n != row.sshCalls {
			t.Fatalf("ssh ran %d times, want %d:\n%s", n, row.sshCalls, data)
		}
	}
	paths, methods := f.requests()
	if row.methods == nil {
		if len(paths) != 0 || (targets != nil && len(*targets) != 0) {
			t.Fatalf("the preview reached FreeIPA (paths %v)", paths)
		}
	} else if !slices.Equal(methods, row.methods) {
		t.Fatalf("methods = %v, want %v", methods, row.methods)
	}
	noPlan(t, plan)
	assertNoSecretAnywhere(t, runErr, out, plan)
}

// runPreviewAndSignal runs the preview and sends sig to this process once
// pidFile exists (the tool it is stalled in is running, so the signal handlers
// are installed). It returns what the run returned and how long after the
// signal.
func runPreviewAndSignal(t *testing.T, args []string, sig syscall.Signal, pidFile string) (string, time.Duration, error) {
	t.Helper()
	resetReconcileFlags()
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"reconcile"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() { resetReconcileFlags(); rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	done := make(chan error, 1)
	go func() { done <- rootCmd.ExecuteContext(context.Background()) }()
	waitForPID(t, pidFile, 30*time.Second)
	begin := time.Now()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		return out.String(), time.Since(begin), err
	case <-time.After(60 * time.Second):
		t.Fatalf("%v did not end the preview within a minute", sig)
		return "", 0, nil
	}
}

// SIGHUP that was ignored when pilot started (nohup) stays ignored: Notify
// would turn the ignore off, and a preview run under nohup would then end
// when the terminal closes, which is what nohup is there to prevent. The
// preview runs in a child of the test binary started with SIGHUP ignored, is
// sent one, and must carry on until its own deadline.
func TestReconcileGolangLeavesAnIgnoredHangupAlone(t *testing.T) {
	const marker = "PILOT_TEST_HANGUP_IGNORED_CHILD"
	if os.Getenv(marker) == "1" {
		if !signalIgnoredAtStart(syscall.SIGHUP) {
			t.Fatal("this process was not started with SIGHUP ignored: the row would prove nothing")
		}
		pids := os.Getenv(childPIDsEnv)
		f := newFakeIPA(t, "p1-self")
		withFakeDialer(t, f)
		dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
		fakeTool(t, "ansible-inventory", stall(pids, "child"))
		out, elapsed, err := runPreviewAndSignal(t, previewArgs("--timeout", "4s", "--plan-out", filepath.Join(dir, "plan.json")), syscall.SIGHUP, filepath.Join(pids, "pid.child"))
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v after %s, want the deadline: the hangup ended the preview\n%s", err, elapsed, out)
		}
		if elapsed < 2*time.Second {
			t.Fatalf("the preview ended %s after the hangup: it was not left alone", elapsed)
		}
		return
	}
	pids := t.TempDir()
	t.Setenv(childPIDsEnv, pids)
	t.Cleanup(func() { killRecorded(pids) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// trap '' HUP makes the shell ignore it, and exec keeps that.
	cmd := exec.CommandContext(ctx, "sh", "-c", `trap '' HUP; exec "$0" "$@"`, exe, "-test.run=^TestReconcileGolangLeavesAnIgnoredHangupAlone$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), marker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestReconcileGolangLeavesAnIgnoredHangupAlone") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// After a preview that went through, nothing is left running: the keep-alive
// tunnel the session was read over is closed with the client, not at process
// exit.
func TestReconcileGolangLeavesNoTunnelAfterAPreview(t *testing.T) {
	w, plan := successRun(t, false)
	if got := len(recordedPIDs(t, w.pids, "tunnel.*")); got < 1 {
		t.Fatalf("recorded %d tunnels", got)
	}
	// No grace: a tunnel is reaped when the preview returns, not later.
	if left := unreapedAtReturn(t, w.pids, []string{"tunnel.*"}); len(left) != 0 {
		t.Fatalf("still running or unreaped when the preview returned: %v", left)
	}
	if _, err := os.Stat(plan); err != nil {
		t.Fatalf("no plan: %v", err)
	}
}

// successRun is the whole preview over the real sshdial.Dialer and a fake ssh
// whose tunnel is a relay to the fake FreeIPA, with the roster encrypted so
// that ansible-vault runs too. Every tool records its process's stat first.
func successRun(t *testing.T, recordSessions bool) (*childWorld, string) {
	t.Helper()
	pids := t.TempDir()
	t.Setenv(childPIDsEnv, pids)
	t.Cleanup(func() { killRecorded(pids) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(childExeEnv, exe)
	f := newFakeIPA(t, "p1-self")
	roster := strings.Replace(captureRoster, "%s", "/bin/sh", 1)
	dir := golangWorkspace(t, roster, nil)
	w := &childWorld{t: t, pids: pids, f: f}
	w.fakeSSH(sshHooks{})
	writeEncrypted(t, filepath.Join(".vault", "ipa-identity.yaml"))
	golangFakeVault(t, "cat <<'EOF'\n"+roster+"EOF")
	if recordSessions {
		recordStats(t, pids, "", "ansible-inventory", "ansible", "ansible-vault")
	}
	plan := filepath.Join(dir, "plan.json")
	out, err := runGolangPreview(t, "--plan-out", plan)
	if err != nil || !strings.Contains(out, "沒有任何寫入") {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	return w, plan
}

// recordStats puts, in front of each named tool on PATH, a wrapper that writes
// /proc/<its pid>/stat to stat.<prefix><tool>.<pid> and then runs the tool.
func recordStats(t *testing.T, pids, prefix string, names ...string) {
	t.Helper()
	bin := t.TempDir()
	prev := os.Getenv("PATH")
	for _, name := range names {
		body := "#!/bin/sh\ncat /proc/$$/stat > \"" + filepath.Join(pids, "stat."+prefix+name+".") + "$$\"\nPATH='" + prev + "' exec " + name + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+prev)
}

// statOf is one recorded /proc/<pid>/stat: the pid, process group and session.
type statOf struct{ pid, pgrp, session string }

func recordedStats(t *testing.T, pids, name string) []statOf {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(pids, "stat."+name+".*"))
	if err != nil {
		t.Fatal(err)
	}
	var out []statOf
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
		if len(fields) < 4 {
			t.Fatalf("%s: %q", f, data)
		}
		out = append(out, statOf{pid: strings.Fields(string(data))[0], pgrp: fields[2], session: fields[3]})
	}
	return out
}

func ownSession(t *testing.T) (pgrp, session string) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	return fields[2], fields[3]
}

// Every child the Go preview starts (ansible-inventory, ansible --list-hosts,
// ansible-vault and every ssh) leads a session of its own, so that a group
// kill reaches it and what it started; the Ansible engine's callers of the
// same builder do not (their terminal signals still reach their children).
func TestReconcileGolangEveryChildLeadsItsOwnSession(t *testing.T) {
	w, _ := successRun(t, true)
	myPgrp, mySession := ownSession(t)
	for _, tool := range []string{"ansible-inventory", "ansible", "ansible-vault", "ssh"} {
		stats := recordedStats(t, w.pids, tool)
		if len(stats) == 0 {
			t.Errorf("%s never ran, so the row proves nothing about it", tool)
		}
		if tool == "ssh" && len(stats) < 3 {
			t.Errorf("ssh ran %d times, want the FQDN, the CA and a tunnel at least", len(stats))
		}
		for _, s := range stats {
			if s.pgrp != s.pid || s.session != s.pid || s.session == mySession {
				t.Errorf("%s (pid %s) has process group %s and session %s (pilot's: %s, %s): want a session of its own", tool, s.pid, s.pgrp, s.session, myPgrp, mySession)
			}
		}
	}

	// The same builder for a caller that is not the Go preview: no new session.
	recordStats(t, w.pids, "plain-", "ansible")
	hosts, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", "")
	if err != nil || !slices.Equal(hosts, []string{"ipa-1"}) {
		t.Fatalf("resolvePatternHosts: %v, %v", hosts, err)
	}
	plain := recordedStats(t, w.pids, "plain-ansible")
	if len(plain) != 1 {
		t.Fatalf("recorded %d plain runs, want 1", len(plain))
	}
	if plain[0].session != mySession || plain[0].pgrp != myPgrp {
		t.Errorf("a caller outside the Go preview got process group %s and session %s, want pilot's own (%s, %s)", plain[0].pgrp, plain[0].session, myPgrp, mySession)
	}
}

// The builder every Ansible command of pilot goes through changes only for a
// context the Go preview marked: any other caller gets exactly the command
// exec.CommandContext and the runtime environment made, as before.
func TestDeployAnsibleCommandIsolatesOnlyForTheGolangPreview(t *testing.T) {
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := withDeployAnsibleRuntime(context.Background(), runtime)

	want := exec.CommandContext(base, "ansible", "host", "-i", "inv", "--list-hosts")
	want.Env = append(os.Environ(), runtime.Env...)
	derived := func(parent context.Context) context.Context {
		ctx, cancel := context.WithTimeout(parent, time.Hour)
		t.Cleanup(cancel)
		return ctx
	}
	for name, ctx := range map[string]context.Context{"a plain context": base, "a derived one": derived(base)} {
		got := deployAnsibleCommand(ctx, "ansible", "host", "-i", "inv", "--list-hosts")
		same := got.Path == want.Path && slices.Equal(got.Args, want.Args) && slices.Equal(got.Env, want.Env) && got.Dir == want.Dir &&
			got.SysProcAttr == nil && got.WaitDelay == 0 && got.Cancel != nil && want.Cancel != nil &&
			got.Stdin == nil && got.Stdout == nil && got.Stderr == nil && got.ExtraFiles == nil && got.Process == nil
		if !same {
			t.Errorf("%s: the command differs from the one exec.CommandContext makes: SysProcAttr=%v WaitDelay=%s Cancel=%v", name, got.SysProcAttr, got.WaitDelay, got.Cancel != nil)
		}
	}

	marked := withIsolatedChildren(base)
	for name, ctx := range map[string]context.Context{"the marked context": marked, "one derived from it": derived(marked)} {
		got := deployAnsibleCommand(ctx, "ansible", "host")
		if got.SysProcAttr == nil || !got.SysProcAttr.Setsid || got.WaitDelay != childproc.WaitDelay || got.Cancel == nil {
			t.Errorf("%s: SysProcAttr=%+v WaitDelay=%s Cancel=%v, want a new session, the wait delay and a group kill", name, got.SysProcAttr, got.WaitDelay, got.Cancel != nil)
		}
		if !slices.Equal(got.Env, want.Env) {
			t.Errorf("%s: the runtime environment is gone from the isolated command", name)
		}
	}
	// Marking a context does not leak into the one it came from.
	if got := deployAnsibleCommand(base, "ansible"); got.SysProcAttr != nil {
		t.Error("marking a derived context isolated the parent's commands")
	}
}

// Only the Go preview marks its context: every other command of pilot cancels
// its context on no signal, so its children must keep the terminal's signals.
// Opting one in is a decision (spec §2.5): it must also handle SIGINT, SIGTERM
// and SIGHUP, so it has to change this list knowingly.
func TestIsolatedChildrenIsSetOnlyByTheGolangPreview(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`\bwithIsolatedChildren\(`)
	var users []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if call.Match(data) {
			users = append(users, f)
		}
	}
	sort.Strings(users)
	if want := []string{"deploy.go", "reconcile_golang.go"}; !slices.Equal(users, want) {
		t.Fatalf("withIsolatedChildren is used by %v, want %v (its definition and the Go preview)", users, want)
	}
	src, err := os.ReadFile("reconcile_golang.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`signal\.NotifyContext\(withIsolatedChildren\(`).Match(src) {
		t.Fatal("the Go preview marks its children as isolated outside the context that handles the signals")
	}
}

// resolvePatternHosts is shared with every deploy path: a context that ended
// is never "no hosts", and anything else about "no hosts" is as it was.
func TestResolvePatternHostsContextEndIsNotZeroHosts(t *testing.T) {
	const noHosts = "echo '[ERROR]: Specified inventory, host pattern and/or --limit leaves us with no hosts to target.' >&2\n"
	t.Run("the context ended while ansible ran", func(t *testing.T) {
		fakeTool(t, "ansible", noHosts+"exec sleep 300")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		hosts, err := resolvePatternHosts(ctx, "inventory.yml", "freeipa-server", "ipa-1")
		if !errors.Is(err, context.DeadlineExceeded) || hosts != nil {
			t.Fatalf("hosts = %v, err = %v, want the deadline", hosts, err)
		}
	})
	t.Run("ansible said no hosts and the context is alive", func(t *testing.T) {
		fakeTool(t, "ansible", noHosts+"exit 1")
		hosts, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", "ipa-1")
		if err != nil || hosts == nil || len(hosts) != 0 {
			t.Fatalf("hosts = %v, err = %v, want an empty list and no error", hosts, err)
		}
	})
	t.Run("another failure with the context alive", func(t *testing.T) {
		fakeTool(t, "ansible", "echo '[ERROR]: synthetic' >&2\nexit 4")
		hosts, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", "ipa-1")
		var exit *exec.ExitError
		if err == nil || hosts != nil || !errors.As(err, &exit) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("hosts = %v, err = %v, want the ExitError with no context error", hosts, err)
		}
	})
	t.Run("the inventory load names the deadline too", func(t *testing.T) {
		golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
		fakeTool(t, "ansible-inventory", "exec sleep 300")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := loadDeployInventorySnapshot(ctx, "inventory.yml")
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "ansible-inventory --list") {
			t.Fatalf("err = %v, want the deadline", err)
		}
	})
}
