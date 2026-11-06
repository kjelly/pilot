//go:build identity_live_hooks

package livehooks

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// driver is the test's side of the protocol: it reads the stops from notify and answers
// them with go.<n>.
type driver struct {
	t   *testing.T
	dir string
}

func newDriver(t *testing.T, points string) *driver {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvDir, dir)
	t.Setenv(EnvPoints, points)
	seq.Store(0)
	return &driver{t: t, dir: dir}
}

// waitFor returns the number of the stop of point, waiting for it to be notified.
func (d *driver) waitFor(point string, within time.Duration) (int, bool) {
	d.t.Helper()
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if f, err := os.Open(filepath.Join(d.dir, "notify")); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				var n int
				var p string
				if _, err := fmt.Sscanf(sc.Text(), "%d %s", &n, &p); err == nil && p == point {
					f.Close()
					return n, true
				}
			}
			f.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, false
}

func (d *driver) answer(n int, what string) {
	d.t.Helper()
	if err := os.WriteFile(filepath.Join(d.dir, fmt.Sprintf("go.%d", n)), []byte(what+"\n"), 0o600); err != nil {
		d.t.Fatal(err)
	}
}

func TestPauseStopsUntilTheDriverAnswersAndOnlyAtTheNamedPoints(t *testing.T) {
	d := newDriver(t, "before_stage:S3, after_entry")
	// A point that was not named does not stop and leaves nothing.
	unnamed := make(chan struct{})
	go func() {
		Pause(context.Background(), "before_stage:S4")
		close(unnamed)
	}()
	select {
	case <-unnamed:
	case <-time.After(2 * time.Second):
		t.Fatal("a point that was not asked for stopped")
	}
	if _, err := os.Stat(filepath.Join(d.dir, "notify")); err == nil {
		t.Fatal("a point that was not asked for was notified")
	}
	released := make(chan struct{})
	go func() {
		Pause(context.Background(), "before_stage:S3")
		close(released)
	}()
	n, ok := d.waitFor("before_stage:S3", 5*time.Second)
	if !ok {
		t.Fatal("the stop was not notified")
	}
	select {
	case <-released:
		t.Fatal("Pause returned before the driver answered")
	case <-time.After(150 * time.Millisecond):
	}
	d.answer(n, "resume")
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("Pause did not return after the answer")
	}
}

func TestPauseEndsWhenItsContextDoes(t *testing.T) {
	d := newDriver(t, "after_entry")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Pause(ctx, "after_entry")
		close(done)
	}()
	if _, ok := d.waitFor("after_entry", 5*time.Second); !ok {
		t.Fatal("the stop was not notified")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stop outlived the cancellation of its context: SIGINT at a stop would hang pilot")
	}
}

// tunnel is a TLS server behind a connection that goes through WrapConn, as the
// freeiparpc client reaches FreeIPA: the request goes out, the answer comes back, and a
// stop holds the answer.
type tunnel struct {
	srv    *httptest.Server
	client *http.Client
	mu     sync.Mutex
	served int
}

func newTunnel(t *testing.T) *tunnel {
	t.Helper()
	tn := &tunnel{}
	tn.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tn.mu.Lock()
		tn.served++
		tn.mu.Unlock()
		_, _ = io.WriteString(w, "answer")
	}))
	tn.srv.StartTLS()
	t.Cleanup(tn.srv.Close)
	addr := tn.srv.Listener.Addr().String()
	tn.client = &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			raw = WrapConn(raw)
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
		MaxIdleConnsPerHost: 1,
	}}
	t.Cleanup(tn.client.CloseIdleConnections)
	return tn
}

func (tn *tunnel) get(ctx context.Context) (string, error) {
	// A POST, as the client's requests are: net/http does not retry one that was written,
	// so a dropped answer is the call's error.
	req, err := http.NewRequestWithContext(RequestContext(ctx), http.MethodPost, "https://tunnel.invalid/x", strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	resp, err := tn.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func (tn *tunnel) servedCount() int {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	return tn.served
}

// The case the driver needs: the request has left and the server has handled it, the answer
// has not been read. Released with resume, the answer arrives; with drop, it never does and the
// client's call fails as one whose tunnel died, having sent the request.
func TestAfterSendHoldsTheAnswerOfTheArmedRequestUntilTheDriverReleasesIt(t *testing.T) {
	for _, tc := range []struct {
		what    string
		wantErr bool
	}{{"resume", false}, {"drop", true}} {
		t.Run(tc.what, func(t *testing.T) {
			d := newDriver(t, "after_send:S3:1")
			tn := newTunnel(t)
			// An earlier request makes the connection the idle, kept-alive one the
			// executor's requests go out on.
			if got, err := tn.get(context.Background()); err != nil || got != "answer" {
				t.Fatalf("the unarmed request: %q, %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(d.dir, "notify")); err == nil {
				t.Fatal("an unarmed request was notified")
			}
			Arm("after_send:S3:1")
			type result struct {
				body string
				err  error
			}
			res := make(chan result, 1)
			go func() {
				b, err := tn.get(context.Background())
				res <- result{b, err}
			}()
			n, ok := d.waitFor("after_send:S3:1", 5*time.Second)
			if !ok {
				t.Fatal("the request was not notified as written")
			}
			// The server handled it (this is what the driver waits for in the server's log)...
			end := time.Now().Add(5 * time.Second)
			for tn.servedCount() < 2 && time.Now().Before(end) {
				time.Sleep(10 * time.Millisecond)
			}
			if tn.servedCount() < 2 {
				t.Fatal("the server did not receive the request that was notified as written")
			}
			// ...and the client has not read the answer.
			select {
			case r := <-res:
				t.Fatalf("the call returned (%q, %v) while its answer was held", r.body, r.err)
			case <-time.After(300 * time.Millisecond):
			}
			d.answer(n, tc.what)
			select {
			case r := <-res:
				if tc.wantErr && r.err == nil {
					t.Fatalf("dropped answer: the call succeeded with %q", r.body)
				}
				if !tc.wantErr && (r.err != nil || r.body != "answer") {
					t.Fatalf("released answer: %q, %v", r.body, r.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the call did not return after the answer")
			}
			// What was armed was one request: the next is not held, not notified.
			if !tc.wantErr {
				before, _ := os.ReadFile(filepath.Join(d.dir, "notify"))
				if got, err := tn.get(context.Background()); err != nil || got != "answer" {
					t.Fatalf("the request after the armed one: %q, %v", got, err)
				}
				after, _ := os.ReadFile(filepath.Join(d.dir, "notify"))
				if string(before) != string(after) {
					t.Fatalf("the request after the armed one was notified:\n%s", strings.TrimPrefix(string(after), string(before)))
				}
			}
		})
	}
}

// A request that is cancelled while its answer is held ends: the hold does not outlive the
// connection (SIGINT and --timeout at after_send, A17).
func TestAHeldAnswerEndsWhenTheRequestIsCancelled(t *testing.T) {
	d := newDriver(t, "after_send:S3:1")
	tn := newTunnel(t)
	if _, err := tn.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	Arm("after_send:S3:1")
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() {
		_, err := tn.get(ctx)
		res <- err
	}()
	if _, ok := d.waitFor("after_send:S3:1", 5*time.Second); !ok {
		t.Fatal("not notified")
	}
	cancel()
	select {
	case err := <-res:
		if err == nil {
			t.Fatal("a cancelled request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled request stayed held")
	}
}

func TestArmWithoutAConfiguredPointDoesNothing(t *testing.T) {
	d := newDriver(t, "after_send:S3:1")
	tn := newTunnel(t)
	if _, err := tn.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	Arm("after_send:S9:9") // not named by the driver
	if got, err := tn.get(context.Background()); err != nil || got != "answer" {
		t.Fatalf("%q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(d.dir, "notify")); err == nil {
		t.Fatal("a point that was not asked for stopped a request")
	}
}

// The hold itself, without HTTP: a read waits while the connection holds and what the peer
// sent stays unread; Close and drop end the wait with an error, and a release lets the
// data through. The reader that is blocked is the transport's, and it must not outlive the
// connection.
func TestAHeldReadWaitsAndIsEndedByCloseOrDrop(t *testing.T) {
	read := func(c net.Conn) chan error {
		out := make(chan error, 1)
		go func() {
			buf := make([]byte, 8)
			_, err := c.Read(buf)
			out <- err
		}()
		return out
	}
	t.Run("close", func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		h := WrapConn(a).(*holdConn)
		h.startHold()
		res := read(h)
		select {
		case err := <-res:
			t.Fatalf("a held read returned: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		_ = h.Close()
		select {
		case err := <-res:
			if err == nil {
				t.Fatal("a read of a closed connection succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a held read outlived the connection")
		}
	})
	t.Run("drop discards what the peer sent", func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		h := WrapConn(a).(*holdConn)
		h.startHold()
		go func() { _, _ = b.Write([]byte("answer")) }() // sent while held: stays unread
		res := read(h)
		time.Sleep(100 * time.Millisecond)
		h.drop()
		select {
		case err := <-res:
			if err != io.ErrUnexpectedEOF {
				t.Fatalf("a dropped read returned %v, want io.ErrUnexpectedEOF: the answer must not be delivered", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a held read did not end on drop")
		}
	})
	t.Run("release lets the data through", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		h := WrapConn(a).(*holdConn)
		h.startHold()
		go func() { _, _ = b.Write([]byte("answer")) }()
		res := read(h)
		select {
		case err := <-res:
			t.Fatalf("a held read returned: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		h.release()
		select {
		case err := <-res:
			if err != nil {
				t.Fatalf("the released read failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a released read did not return the data")
		}
	})
}
