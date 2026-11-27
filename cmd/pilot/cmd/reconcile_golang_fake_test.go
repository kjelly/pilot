package cmd

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// fakeIPAHalfClosedCall POSTs one JSON-RPC request for method over a TLS
// connection of its own (with a session cookie, as after a login), waits for
// ready (nil: not at all), then sends only the close_notify alert, which is what
// tls.Conn.Close sends before it closes the connection, and returns everything
// the server sends until it ends the connection. ready is signalled by the
// caller's fake.onHang once the server holds the request.
func fakeIPAHalfClosedCall(t *testing.T, f *fakeIPA, method string, ready <-chan struct{}) ([]byte, error) {
	t.Helper()
	raw, err := net.Dial("tcp", f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{RootCAs: f.ca, ServerName: golangTestFQDN})
	t.Cleanup(func() { _ = tc.Close() })
	body := `{"method":"` + method + `","params":[[],{"version":"2.257"}],"id":0}`
	if _, err := fmt.Fprintf(tc, "POST /ipa/session/json HTTP/1.1\r\nHost: %s\r\nCookie: ipa_session=x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", golangTestFQDN, len(body), body); err != nil {
		t.Fatal(err)
	}
	if ready != nil {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatalf("the fake never held %s", method)
		}
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	return io.ReadAll(tc)
}

// A method the fake is told never to answer stays unanswered when the client
// gives up: net/http's cancellation of a TLS request sends close_notify before
// it closes the connection (the tunnel's real close can come later), and a
// reply written then, such as the 200 with an empty body net/http writes for a
// handler that returns without writing, can reach a client whose connection is
// still open and be taken in place of the client's own deadline: "decode
// response: incomplete response" instead of the context error (#313). The
// answered method is the control: the same probe sees a reply when there is one.
func TestFakeIPAHungMethodIsNeverAnswered(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	held := make(chan struct{}, 1)
	f.onHang = func(string) {
		select {
		case held <- struct{}{}:
		default:
		}
	}
	f.hang = map[string]bool{"ping": true}

	got, err := fakeIPAHalfClosedCall(t, f, "session_logout", nil)
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 200 OK\r\n")) || !bytes.Contains(got, []byte(`"error":null`)) {
		t.Fatalf("control: the answered method got %q (read err %v), want the 200 with its JSON-RPC answer", got, err)
	}

	got, err = fakeIPAHalfClosedCall(t, f, "ping", held)
	if len(got) != 0 {
		t.Fatalf("the hung ping was answered after the client's close_notify: %q (read err %v)", got, err)
	}
	// Silence must be the fake ending the connection, not the probe giving up
	// on a connection the fake still holds.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the hung ping's connection was neither answered nor ended after the client's close_notify: %v", err)
	}
}
