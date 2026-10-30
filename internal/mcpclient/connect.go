package mcpclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// maxPreReadyNoise bounds what may precede the ready line (for example
// output from the remote login shell's startup files).
const maxPreReadyNoise = 64 << 10

// sshBinary is the ssh client; a variable so tests can point at a stub.
var sshBinary = "ssh"

// Options is one pilot-mcp invocation against one profile.
type Options struct {
	ProfileName   string
	Profile       Profile
	Image         string // --image; overrides Profile.Target.Image
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	CacheDir      string
	StatePath     string
	ClientVersion string
	ClientUser    string
}

func (o *Options) image() (string, error) {
	img := o.Image
	if img == "" {
		img = o.Profile.Target.Image
	}
	if img == "" {
		return "", &Error{Code: CodeProfileInvalid, Msg: "no image: set target.image in the profile or pass --image <repository>:<tag>"}
	}
	if err := ValidateImage(img); err != nil {
		return "", &Error{Code: CodeProfileInvalid, Msg: "--image: " + err.Error()}
	}
	return img, nil
}

func (o *Options) sshConfig() (string, error) {
	if o.Profile.Target.SSHConfig == "" {
		return "", nil
	}
	return ExpandHome(o.Profile.Target.SSHConfig)
}

// tailBuffer forwards writes and keeps the last max bytes, so the remote's
// error line can be parsed after ssh exits.
type tailBuffer struct {
	mu  sync.Mutex
	out io.Writer
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	if t.out != nil {
		if _, err := t.out.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// sshProc is one running `ssh <host> '<docker run …>'`.
type sshProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	pipe   io.ReadCloser // ssh's stdout, under stdout
	stdout *bufio.Reader
	stderr *tailBuffer

	waitOnce sync.Once
	exit     int
}

func startSSH(o *Options, argv []string, withStdin bool) (*sshProc, error) {
	remote, err := shellJoin(argv)
	if err != nil {
		return nil, &Error{Code: CodeProfileInvalid, Msg: err.Error()}
	}
	cfg, err := o.sshConfig()
	if err != nil {
		return nil, &Error{Code: CodeProfileInvalid, Msg: err.Error()}
	}
	cmd := exec.Command(sshBinary, sshArgs(o.Profile, cfg, remote)...)
	isolate(cmd)
	p := &sshProc{cmd: cmd, stderr: &tailBuffer{out: o.Stderr, max: 64 << 10}}
	cmd.Stderr = p.stderr
	if withStdin {
		if p.stdin, err = cmd.StdinPipe(); err != nil {
			return nil, err
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p.pipe = stdout
	p.stdout = bufio.NewReaderSize(stdout, 64<<10)
	if err := cmd.Start(); err != nil {
		return nil, &Error{Code: CodeSSHFailed, Msg: "start ssh: " + err.Error()}
	}
	return p, nil
}

// wait reaps ssh once its stdout is drained and returns its exit status.
// It may be called more than once.
func (p *sshProc) wait() int {
	p.waitOnce.Do(func() {
		err := p.cmd.Wait()
		var exitErr *exec.ExitError
		switch {
		case err == nil, errors.Is(err, exec.ErrWaitDelay):
			p.exit = 0 // ErrWaitDelay: ssh succeeded; a helper kept a pipe open
		case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
			p.exit = exitErr.ExitCode()
		default:
			p.exit = 255
		}
	})
	return p.exit
}

// kill ends ssh and every helper in its process group, closes its stdout
// (a helper that left the group may still hold it) and reaps it.
func (p *sshProc) kill() {
	_ = killGroup(p.cmd)
	_ = p.pipe.Close()
	p.wait()
}

// readAll reads ssh's stdout to EOF, at most limit bytes. When ctx ends
// first it kills ssh (kill), which unblocks the read, and returns
// ctx.Err().
func (p *sshProc) readAll(ctx context.Context, limit int64) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(p.stdout, limit))
		done <- result{data, err}
	}()
	select {
	case r := <-done:
		return r.data, r.err
	case <-ctx.Done():
		p.kill()
		<-done
		return nil, ctx.Err()
	}
}

// stop closes ssh's stdin, gives the remote 5 seconds to end, then kills
// ssh's process group.
func (p *sshProc) stop() {
	if p.stdin != nil {
		p.stdin.Close()
	}
	exited := make(chan struct{})
	go func() {
		p.wait()
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		p.kill()
		<-exited
	}
}

// readReady reads lines until the ready line, forwarding anything before
// it to stderr. It fails after maxPreReadyNoise bytes or at EOF.
func readReady(r *bufio.Reader, stderr io.Writer) (mcpwire.Ready, error) {
	var noise int
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		noise += len(chunk)
		if errors.Is(err, bufio.ErrBufferFull) {
			if noise > maxPreReadyNoise {
				return mcpwire.Ready{}, fmt.Errorf("no ready line within %d bytes", maxPreReadyNoise)
			}
			continue
		}
		if err != nil {
			return mcpwire.Ready{}, err
		}
		text := string(line)
		line = nil
		if strings.HasPrefix(text, mcpwire.ReadyPrefix) {
			return mcpwire.ParseReady(text)
		}
		fmt.Fprintf(stderr, "pilot-mcp: remote output before the session started: %s", text)
		if noise > maxPreReadyNoise {
			return mcpwire.Ready{}, fmt.Errorf("no ready line within %d bytes", maxPreReadyNoise)
		}
	}
}

// startSession runs everything up to a verified ready line: resolve Git,
// build the snapshot, start the container over SSH, send the snapshot,
// and check the ready line against the profile.
func startSession(ctx context.Context, o *Options) (*sshProc, mcpwire.Ready, *Snapshot, error) {
	image, err := o.image()
	if err != nil {
		return nil, mcpwire.Ready{}, nil, err
	}
	repo, err := openGitCache(o.CacheDir, o.Profile.Source.URL, o.Profile.gitTimeout())
	if err != nil {
		return nil, mcpwire.Ready{}, nil, &Error{Code: CodeGitFailed, Msg: "git cache: " + err.Error()}
	}
	commit, err := repo.resolve(ctx, o.Profile.Source.Ref)
	if err != nil {
		return nil, mcpwire.Ready{}, nil, err
	}
	snap, err := buildSnapshot(ctx, repo, o.Profile.Source, commit, o.Profile.Target.Env, o.ClientVersion, o.ClientUser)
	if err != nil {
		return nil, mcpwire.Ready{}, nil, err
	}
	for _, p := range snap.Removed {
		fmt.Fprintf(o.Stderr, "pilot-mcp: not sent (provided by the deploy node or reserved): %s\n", p)
	}

	proc, err := startSSH(o, sessionCommand(o.Profile.Target, image, o.Profile.Mode), true)
	if err != nil {
		return nil, mcpwire.Ready{}, nil, err
	}
	// Write the snapshot while reading stdout, so neither side blocks the
	// other; a remote that rejects early closes its stdin (EPIPE here).
	go func() { _, _ = proc.stdin.Write(snap.Framed) }()

	type readyResult struct {
		ready mcpwire.Ready
		err   error
	}
	got := make(chan readyResult, 1)
	go func() {
		r, err := readReady(proc.stdout, o.Stderr)
		got <- readyResult{r, err}
	}()
	timer := time.NewTimer(o.Profile.startupTimeout())
	defer timer.Stop()
	var res readyResult
	select {
	case res = <-got:
	case <-timer.C:
		proc.stop()
		return nil, mcpwire.Ready{}, nil, &Error{Code: CodeRemoteRuntime, Msg: fmt.Sprintf("no ready line within %s (timeouts.startup_seconds)", o.Profile.startupTimeout())}
	case <-ctx.Done():
		proc.stop()
		return nil, mcpwire.Ready{}, nil, ctx.Err()
	}
	if res.err != nil {
		if !errors.Is(res.err, io.EOF) && !errors.Is(res.err, io.ErrUnexpectedEOF) {
			// The remote is still running (noise overflow or a malformed
			// ready line); waiting would block.
			proc.stop()
			return nil, mcpwire.Ready{}, nil, &Error{Code: CodeRemoteRuntime, Msg: "session did not start: " + res.err.Error()}
		}
		if exit := proc.wait(); exit != 0 {
			return nil, mcpwire.Ready{}, nil, remoteFailure(exit, proc.stderr.String())
		}
		return nil, mcpwire.Ready{}, nil, &Error{Code: CodeRemoteRuntime, Msg: "the remote ended before the session started"}
	}
	r := res.ready
	if r.Mode != o.Profile.Mode || r.Env != o.Profile.Target.Env {
		proc.stop()
		return nil, mcpwire.Ready{}, nil, &Error{Code: CodeRemoteRejected, Msg: fmt.Sprintf("deploy node started a %s session for %s, the profile asks for %s/%s", r.Mode, r.Env, o.Profile.Mode, o.Profile.Target.Env)}
	}
	if err := appendRecord(o.StatePath, Record{
		Time: time.Now().UTC(), Profile: o.ProfileName, Env: r.Env, Image: image, Mode: r.Mode,
		SessionID: r.SessionID, CommitSHA: r.CommitSHA, ContentDigest: r.ContentDigest,
	}); err != nil {
		fmt.Fprintf(o.Stderr, "pilot-mcp: warning: could not record the session: %v\n", err)
	}
	fmt.Fprintf(o.Stderr, "pilot-mcp: session %s (%s, %s, commit %s)\n", r.SessionID, r.Mode, r.Env, r.CommitSHA)
	return proc, r, snap, nil
}

// Connect is `pilot-mcp connect`: start the session, then relay the
// agent's stdin and stdout until either side ends. Nothing but MCP bytes
// is ever written to Stdout.
func Connect(ctx context.Context, o *Options) error {
	proc, _, _, err := startSession(ctx, o)
	if err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(proc.stdin, o.Stdin)
		proc.stdin.Close()
	}()
	copied := make(chan error, 1)
	go func() {
		// proc.stdout may already hold MCP bytes read past the ready line.
		_, err := io.Copy(o.Stdout, proc.stdout)
		copied <- err
	}()
	select {
	case <-copied:
	case <-ctx.Done():
		proc.stop()
		return ctx.Err()
	}
	if exit := proc.wait(); exit != 0 {
		return remoteFailure(exit, proc.stderr.String())
	}
	return nil
}

// CurrentUser is the local user name recorded (unverified) in the manifest.
func CurrentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}
