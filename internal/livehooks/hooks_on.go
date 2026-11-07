//go:build identity_live_hooks

package livehooks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Enabled reports whether this binary has the injection points: it has.
const Enabled = true

// pollEvery is how often a stop looks for the driver's answer.
const pollEvery = 20 * time.Millisecond

var (
	seq atomic.Int64 // numbers the stops of this process

	// armed is the point of the next request that should have its answer held.
	armMu sync.Mutex
	armed string
)

// configured reports whether the driver asked to stop at point, and where.
func configured(point string) (dir string, ok bool) {
	dir = os.Getenv(EnvDir)
	if dir == "" {
		return "", false
	}
	for _, p := range strings.Split(os.Getenv(EnvPoints), ",") {
		if strings.TrimSpace(p) == point {
			return dir, true
		}
	}
	return "", false
}

// notify appends the stop to the driver's file and returns its number.
func notify(dir, point string) (int64, error) {
	n := seq.Add(1)
	f, err := os.OpenFile(filepath.Join(dir, "notify"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return n, err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d %s\n", n, point)
	return n, err
}

// answer waits for go.<n> and returns what it says; ctx ends the wait ("resume").
func answer(ctx context.Context, dir string, n int64) string {
	path := filepath.Join(dir, fmt.Sprintf("go.%d", n))
	for {
		if data, err := os.ReadFile(path); err == nil {
			if s := strings.TrimSpace(string(data)); s != "" {
				return s
			}
		}
		select {
		case <-ctx.Done():
			return "resume"
		case <-time.After(pollEvery):
		}
	}
}

// Pause stops at point when the driver asked for it, until the driver answers or ctx ends.
func Pause(ctx context.Context, point string) {
	dir, ok := configured(point)
	if !ok {
		return
	}
	n, err := notify(dir, point)
	if err != nil {
		fmt.Fprintf(os.Stderr, "livehooks: cannot notify the driver of %s: %v\n", point, err)
		return
	}
	answer(ctx, dir, n)
}

// Arm marks the next request as the one whose answer is held at point (an after_send
// point), when the driver asked for it.
func Arm(point string) {
	if _, ok := configured(point); !ok {
		return
	}
	armMu.Lock()
	armed = point
	armMu.Unlock()
}

// Armed is the point the next request is armed for, "" when none. It is for the tests of the
// code that calls Arm, which cannot otherwise see what it armed.
func Armed() string {
	armMu.Lock()
	defer armMu.Unlock()
	return armed
}

func takeArmed() string {
	armMu.Lock()
	defer armMu.Unlock()
	p := armed
	armed = ""
	return p
}

// WrapConn wraps the connection of the tunnel so that its reads can be held.
func WrapConn(c net.Conn) net.Conn {
	h := &holdConn{Conn: c}
	h.cond = sync.NewCond(&h.mu)
	return h
}

// holdConn is a net.Conn whose reads can be held back: while it holds, Read returns
// nothing, and what the peer sent stays unread in the pipe.
type holdConn struct {
	net.Conn
	mu      sync.Mutex
	cond    *sync.Cond
	holding bool
	dropped bool
	closed  bool
	// interrupted: a Read in flight was cut short by startHold, and its timeout is ours.
	interrupted bool
	callerDL    time.Time
}

func (c *holdConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.callerDL = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *holdConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.callerDL = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// startHold makes reads wait. A Read already blocked inside the connection (the
// transport's idle read) is cut short with a deadline in the past, so that the answer
// to the request about to be written is not consumed before the driver has acted.
func (c *holdConn) startHold() {
	c.mu.Lock()
	c.holding, c.interrupted = true, true
	c.mu.Unlock()
	_ = c.Conn.SetReadDeadline(time.Now())
}

func (c *holdConn) release() {
	c.mu.Lock()
	c.holding = false
	c.cond.Broadcast()
	c.mu.Unlock()
}

// drop discards what is unread and fails the connection.
func (c *holdConn) drop() {
	c.mu.Lock()
	c.dropped, c.holding = true, false
	c.cond.Broadcast()
	c.mu.Unlock()
	_ = c.Conn.Close()
}

func (c *holdConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		for c.holding && !c.closed && !c.dropped {
			c.cond.Wait()
		}
		switch {
		case c.dropped:
			c.mu.Unlock()
			return 0, io.ErrUnexpectedEOF
		case c.closed:
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		c.mu.Unlock()
		n, err := c.Conn.Read(b)
		if err != nil {
			c.mu.Lock()
			own := c.interrupted
			c.interrupted = false
			dl := c.callerDL
			c.mu.Unlock()
			if own {
				_ = c.Conn.SetReadDeadline(dl)
				if n == 0 {
					continue
				}
			}
		}
		return n, err
	}
}

func (c *holdConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.Conn.Close()
}

// RequestContext attaches the trace that finds the connection an armed request goes
// out on, holds its answer, and tells the driver when the request has been written.
func RequestContext(ctx context.Context) context.Context {
	point := takeArmed()
	if point == "" {
		return ctx
	}
	var (
		bound *holdConn
		once  sync.Once // the trace fires again for a retry of the request: the hold is for the first connection only
	)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if bound != nil {
				return
			}
			if nc, ok := info.Conn.(interface{ NetConn() net.Conn }); ok {
				if hc, ok := nc.NetConn().(*holdConn); ok {
					bound = hc
					hc.startHold()
				}
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			hc := bound
			if hc == nil {
				return
			}
			first := false
			once.Do(func() { first = true })
			if !first {
				return
			}
			dir, ok := configured(point)
			if !ok {
				hc.release()
				return
			}
			n, err := notify(dir, point)
			if err != nil {
				fmt.Fprintf(os.Stderr, "livehooks: cannot notify the driver of %s: %v\n", point, err)
				hc.release()
				return
			}
			go func() {
				// The wait is not tied to the request's context: a cancelled request closes
				// the connection, which ends the hold on its own.
				if answer(context.Background(), dir, n) == "drop" {
					hc.drop()
					return
				}
				hc.release()
			}()
		},
	})
}
