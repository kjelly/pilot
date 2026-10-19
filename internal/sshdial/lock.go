package sshdial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DefaultLockPath is what the remote lock flocks: a directory every FreeIPA
// server has and every SSH identity can open read-only, so no lock file has
// to be created (a file in a shared sticky /tmp would run into
// fs.protected_regular for the next user).
const DefaultLockPath = "/etc/ipa"

// lockBusyExit is the exit status flock is told to use when the wait runs
// out.
const lockBusyExit = 75

var lockPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// Lock is an exclusive lock held on the server for as long as its ssh
// session lives: flock holds it while `cat` waits on stdin, so closing
// stdin releases it and a dropped SSH connection ends the session and
// releases it too.
type Lock struct {
	p     *process
	stdin io.WriteCloser
}

// LockOptions tune AcquireLock.
type LockOptions struct {
	Path string        // default DefaultLockPath
	Wait time.Duration // how long to wait for another holder; 0 fails at once
}

// AcquireLock takes the server-wide reconcile lock. It returns ErrLockBusy
// (in a *TunnelError) when another holder keeps it past opts.Wait.
func (d *Dialer) AcquireLock(ctx context.Context, opts LockOptions) (*Lock, error) {
	if err := d.Target.Validate(); err != nil {
		return nil, err
	}
	path := opts.Path
	if path == "" {
		path = DefaultLockPath
	}
	if !lockPathRe.MatchString(path) || strings.Contains(path, "..") {
		return nil, fmt.Errorf("sshdial: invalid lock path %q", path)
	}
	wait := "--nonblock"
	if opts.Wait > 0 {
		wait = fmt.Sprintf("--wait %d", int(opts.Wait.Round(time.Second)/time.Second))
	}
	command := fmt.Sprintf("flock %s --conflict-exit-code %d %s sh -c 'echo locked; exec cat'", wait, lockBusyExit, path)
	// Not CommandContext: the lock outlives the context that acquired it.
	cmd := exec.Command(d.program(), d.Target.args()...)
	cmd.Args = append(cmd.Args, command)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p, err := start(cmd)
	if err != nil {
		return nil, err
	}
	locked := make(chan bool, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		locked <- strings.TrimSpace(line) == "locked"
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case ok := <-locked:
		if ok {
			return &Lock{p: p, stdin: stdin}, nil
		}
		stdin.Close()
		f := p.failure()
		var te *TunnelError
		if errors.As(f, &te) && te.ExitCode == lockBusyExit {
			te.Kind = ErrLockBusy
			return nil, te
		}
		if f == nil {
			f = errors.New("the lock command ended without taking the lock")
		}
		return nil, fmt.Errorf("sshdial: acquire lock on %s: %w", path, f)
	case <-ctx.Done():
		stdin.Close()
		p.kill()
		return nil, fmt.Errorf("sshdial: acquire lock on %s: %w", path, ctx.Err())
	}
}

// Lost is closed when the lock's ssh session ends without Release: from
// then on another run can take the lock, so no further write may be sent.
func (l *Lock) Lost() <-chan struct{} { return l.p.done }

// Release gives the lock back and waits for the session to end.
func (l *Lock) Release() error {
	l.stdin.Close()
	select {
	case <-l.p.done:
	case <-time.After(10 * time.Second):
		l.p.kill()
	}
	return nil
}
