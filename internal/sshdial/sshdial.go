// Package sshdial reaches a FreeIPA server through the system OpenSSH
// client: `ssh -W` forwards one TCP connection per net.Conn, and a few fixed
// remote commands read the server's FQDN and CA certificate and hold an
// exclusive lock. Nothing caller-supplied ever reaches a remote command, and
// no local port is opened (docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md §3).
package sshdial

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultDestination is where the server side of the tunnel connects: the
// FreeIPA server's own loopback HTTPS port.
const DefaultDestination = "127.0.0.1:443"

// allowedOptions are the `-o` options a Target may set. Anything else is
// rejected before ssh runs rather than passed through unexamined.
var allowedOptions = map[string]bool{
	"ConnectTimeout":        true,
	"ProxyJump":             true,
	"ServerAliveCountMax":   true,
	"ServerAliveInterval":   true,
	"StrictHostKeyChecking": true,
	"UserKnownHostsFile":    true,
}

// Target is the SSH destination: the FreeIPA server Pilot writes to.
type Target struct {
	Host         string            // address or name given to ssh
	User         string            // empty: ssh's default
	Port         int               // 0: ssh's default
	IdentityFile string            // empty: ssh's default identities
	Options      map[string]string // `-o Key=Value`; keys must be in allowedOptions
}

var (
	hostRe        = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]+$`)
	userRe        = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)
	optionValueRe = regexp.MustCompile(`^[A-Za-z0-9._,:@/+=-]+$`)
)

// Validate reports a Target ssh cannot be given safely.
func (t Target) Validate() error {
	if !hostRe.MatchString(t.Host) || strings.HasPrefix(t.Host, "-") {
		return fmt.Errorf("sshdial: invalid host %q", t.Host)
	}
	if t.User != "" && !userRe.MatchString(t.User) {
		return fmt.Errorf("sshdial: invalid user %q", t.User)
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("sshdial: invalid port %d", t.Port)
	}
	for k, v := range t.Options {
		if !allowedOptions[k] {
			return fmt.Errorf("sshdial: ssh option %q is not supported", k)
		}
		if !optionValueRe.MatchString(v) {
			return fmt.Errorf("sshdial: invalid value for ssh option %s", k)
		}
	}
	return nil
}

// args returns ssh's argv (without the program name) up to and including
// the destination; extra goes before the destination.
func (t Target) args(extra ...string) []string {
	// BatchMode: never prompt. ControlPath=none: never reuse another
	// process's master connection. ClearAllForwardings: no forwarding
	// from ssh_config besides the one -W asks for.
	a := []string{"-o", "BatchMode=yes", "-o", "ControlPath=none", "-o", "ClearAllForwardings=yes"}
	keys := make([]string, 0, len(t.Options))
	for k := range t.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "-o", k+"="+t.Options[k])
	}
	if t.Port != 0 {
		a = append(a, "-p", strconv.Itoa(t.Port))
	}
	if t.IdentityFile != "" {
		a = append(a, "-i", t.IdentityFile)
	}
	if t.User != "" {
		a = append(a, "-l", t.User)
	}
	a = append(a, extra...)
	return append(a, "--", t.Host)
}

// Errors a tunnel or remote command can end with. They are wrapped in a
// *TunnelError carrying ssh's own message.
var (
	// ErrForwardingDenied: sshd refused the forwarding (AllowTcpForwarding
	// no, DisableForwarding yes, or PermitOpen without the destination).
	ErrForwardingDenied = errors.New("sshd refused the TCP forwarding")
	// ErrDestinationRefused: sshd tried, but nothing accepted the
	// connection at the destination.
	ErrDestinationRefused = errors.New("the forwarding destination refused the connection")
	// ErrSSH: ssh failed for another reason (authentication, host key,
	// network).
	ErrSSH = errors.New("ssh failed")
	// ErrLockBusy: another holder kept the remote lock past the wait.
	ErrLockBusy = errors.New("the remote reconcile lock is held by another run")
)

// TunnelError is an ssh failure with ssh's stderr (it never contains
// anything Pilot sent through the tunnel).
type TunnelError struct {
	Kind     error
	ExitCode int
	Stderr   string
}

func (e *TunnelError) Error() string {
	// ssh ends its stderr lines with \r\n; one line reads better in logs.
	var lines []string
	for _, l := range strings.Split(e.Stderr, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	msg := strings.Join(lines, "; ")
	if msg == "" {
		msg = "no message"
	}
	return fmt.Sprintf("%v (ssh exit %d): %s", e.Kind, e.ExitCode, msg)
}

func (e *TunnelError) Unwrap() error { return e.Kind }

// classify maps ssh's exit and stderr to a TunnelError. The messages are
// OpenSSH's (testdata holds real captures).
func classify(exitCode int, stderr string) *TunnelError {
	kind := ErrSSH
	switch {
	case strings.Contains(stderr, "administratively prohibited"):
		kind = ErrForwardingDenied
	case strings.Contains(stderr, "open failed: connect failed"):
		kind = ErrDestinationRefused
	}
	return &TunnelError{Kind: kind, ExitCode: exitCode, Stderr: stderr}
}

// boundedBuffer keeps the first n bytes written to it.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	n   int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.n - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// process is a started ssh with its exit status collected in the
// background, so readers never race exec.Cmd.Wait.
type process struct {
	cmd    *exec.Cmd
	stderr *boundedBuffer
	done   chan struct{}
	err    error
}

func start(cmd *exec.Cmd) (*process, error) {
	p := &process{cmd: cmd, stderr: &boundedBuffer{n: 4096}, done: make(chan struct{})}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sshdial: start ssh: %w", err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// failure returns the ssh failure after the process exited, or nil when it
// exited 0.
func (p *process) failure() error {
	<-p.done
	if p.err == nil {
		return nil
	}
	code := -1
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		code = ee.ExitCode()
	}
	return classify(code, p.stderr.String())
}

func (p *process) kill() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	<-p.done
}

// Dialer opens one `ssh -W` per connection. It is safe for concurrent use.
type Dialer struct {
	Target      Target
	Destination string // default DefaultDestination
	SSH         string // ssh program; default "ssh" from PATH
}

func (d *Dialer) program() string {
	if d.SSH != "" {
		return d.SSH
	}
	return "ssh"
}

func (d *Dialer) destination() (string, error) {
	dest := d.Destination
	if dest == "" {
		dest = DefaultDestination
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil || !hostRe.MatchString(host) {
		return "", fmt.Errorf("sshdial: invalid forwarding destination %q", dest)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("sshdial: invalid forwarding destination %q", dest)
	}
	return dest, nil
}

// DialContext starts `ssh -W <destination>` and returns its stdin/stdout as
// a net.Conn. It ignores network and addr: the destination is fixed, so a
// URL can never steer the tunnel elsewhere. It fits http.Transport.DialContext.
func (d *Dialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if err := d.Target.Validate(); err != nil {
		return nil, err
	}
	dest, err := d.destination()
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	// Not CommandContext: the connection outlives the dial's context.
	cmd := exec.Command(d.program(), d.Target.args("-W", dest)...)
	cmd.Stdin, cmd.Stdout = inR, outW
	p, err := start(cmd)
	inR.Close()
	outW.Close()
	if err != nil {
		inW.Close()
		outR.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		p.kill()
		inW.Close()
		outR.Close()
		return nil, ctx.Err()
	}
	return &conn{p: p, r: outR, w: inW, dest: dest}, nil
}

// conn is a net.Conn over an ssh -W process.
type conn struct {
	p         *process
	r         *os.File
	w         *os.File
	dest      string
	closeOnce sync.Once
	closed    atomic.Bool
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if err != nil && c.closed.Load() {
		// Closed on this side: ssh was killed on purpose, not failing.
		return n, net.ErrClosed
	}
	if errors.Is(err, io.EOF) {
		// ssh closed its stdout. A failed ssh explains why; a clean exit
		// is the server closing the connection.
		select {
		case <-c.p.done:
		case <-time.After(5 * time.Second):
			return n, err
		}
		if f := c.p.failure(); f != nil {
			return n, f
		}
	}
	return n, err
}

func (c *conn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.w.Close()
		c.p.kill()
		c.r.Close()
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return pipeAddr("ssh") }
func (c *conn) RemoteAddr() net.Addr { return pipeAddr(c.dest) }

func (c *conn) SetDeadline(t time.Time) error {
	if err := c.r.SetReadDeadline(t); err != nil {
		return err
	}
	return c.w.SetWriteDeadline(t)
}
func (c *conn) SetReadDeadline(t time.Time) error  { return c.r.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.w.SetWriteDeadline(t) }

type pipeAddr string

func (a pipeAddr) Network() string { return "ssh-W" }
func (a pipeAddr) String() string  { return string(a) }

// run executes a fixed remote command and returns its stdout.
func (d *Dialer) run(ctx context.Context, command string) ([]byte, error) {
	if err := d.Target.Validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, d.program(), d.Target.args()...)
	cmd.Args = append(cmd.Args, command)
	cmd.Stdout = &out
	p, err := start(cmd)
	if err != nil {
		return nil, err
	}
	if f := p.failure(); f != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("sshdial: %s: %w", command, ctx.Err())
		}
		return nil, fmt.Errorf("sshdial: %s: %w", command, f)
	}
	return out.Bytes(), nil
}

var fqdnRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// FQDN returns the server's fully qualified name (`hostname -f`), in lower
// case. TLS, the request URL and the Referer all use it.
func (d *Dialer) FQDN(ctx context.Context) (string, error) {
	out, err := d.run(ctx, "hostname -f")
	if err != nil {
		return "", err
	}
	fqdn := strings.ToLower(strings.TrimSpace(string(out)))
	if !fqdnRe.MatchString(fqdn) {
		return "", fmt.Errorf("sshdial: hostname -f returned %q, not a fully qualified name", fqdn)
	}
	return fqdn, nil
}

// CAPath is where every FreeIPA server and client keeps the IPA CA.
const CAPath = "/etc/ipa/ca.crt"

// CA reads the IPA CA certificate over SSH (whose host key ssh verified)
// and returns a pool holding only it.
func (d *Dialer) CA(ctx context.Context) (*x509.CertPool, error) {
	out, err := d.run(ctx, "cat "+CAPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(out) {
		return nil, fmt.Errorf("sshdial: %s holds no PEM certificate", CAPath)
	}
	return pool, nil
}
