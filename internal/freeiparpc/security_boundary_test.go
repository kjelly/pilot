package freeiparpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// These are hostile-response fault injections, not FreeIPA captures.
func TestRedirectsNeverResendSessionRequests(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, dest := range []string{"plaintext", "other-origin", "same-origin", "malformed-location"} {
			for _, operation := range []string{"login", "read", "write", "logout"} {
				t.Run(fmt.Sprintf("%d/%s/%s", status, dest, operation), func(t *testing.T) {
					var leaked atomic.Int32
					sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						leaked.Add(1)
						_, _ = io.Copy(io.Discard, r.Body)
					}))
					defer sink.Close()
					f := newFakeServer(t, testFQDN)
					f.answer = byMethod(map[string]string{"user_show": "user-show", "user_mod": "user-mod"})
					c := newTestClient(t, f)
					var armed atomic.Bool
					original := f.srv.Config.Handler
					f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/leaked" {
							leaked.Add(1)
							return
						}
						if armed.Load() {
							location := "https://" + testFQDN + "/leaked"
							if dest == "plaintext" {
								location = sink.URL + "/leaked"
							}
							if dest == "other-origin" {
								location = "https://other.example.test/leaked"
							}
							if dest == "malformed-location" {
								location = "http://%invalid/"
							}
							w.Header().Set("Location", location+"?secret="+testPassword)
							w.WriteHeader(status)
							return
						}
						original.ServeHTTP(w, r)
					})
					ctx := context.Background()
					if operation != "login" {
						if err := c.Login(ctx, "admin", testPassword); err != nil {
							t.Fatal(err)
						}
					}
					armed.Store(true)
					var err error
					switch operation {
					case "login":
						err = c.Login(ctx, "admin", testPassword)
					case "read":
						_, err = c.Call(ctx, Command{Method: "user_show", Args: []any{"a"}})
					case "write":
						_, err = c.Call(ctx, Command{Method: "user_mod", Args: []any{"a"}})
					case "logout":
						err = c.Logout(ctx)
					}
					if err == nil {
						t.Error("redirect was reported successful")
					}
					if err != nil && strings.Contains(err.Error(), testPassword) {
						t.Error("error disclosed redirect secret")
					}
					if got := leaked.Load(); got != 0 {
						t.Errorf("redirect sent %d requests outside the original endpoint", got)
					}
					var unknown *OutcomeUnknownError
					if operation == "write" && (!errors.As(err, &unknown) || c.Stats().Unknown != 1) {
						t.Errorf("write redirect lacks unknown classification: %T, %+v", err, c.Stats())
					}
					if c.Stats().ReadRetries != 0 {
						t.Error("redirect was retried")
					}
				})
			}
		}
	}
}

func TestMissingErrorNeverConfirmsAnOutcome(t *testing.T) {
	for _, method := range []string{"user_mod", "user_show", "ping", "session_logout", "batch-read", "batch-write", "batch-envelope-read", "batch-envelope-write"} {
		t.Run(method, func(t *testing.T) {
			f, c := loggedIn(t, nil)
			response := `{"result":{"result":{"uid":["a"]}}}`
			if method == "ping" {
				response = `{"result":{"summary":"IPA server version 4.13.4. API version 2.257"}}`
			}
			if strings.HasPrefix(method, "batch-") {
				response = `{"error":null,"result":{"count":1,"results":[{"result":{}}]}}`
			}
			if strings.HasPrefix(method, "batch-envelope-") {
				response = `{"result":{"count":1,"results":[{"error":null,"result":{}}]}}`
			}
			f.hook = func(w http.ResponseWriter, _ string) bool { _, _ = io.WriteString(w, response); return true }
			f.logoutBody = response
			var err error
			switch method {
			case "session_logout":
				err = c.Logout(context.Background())
			case "batch-read", "batch-envelope-read":
				_, err = c.Batch(context.Background(), []Command{{Method: "user_show"}})
			case "batch-write", "batch-envelope-write":
				_, err = c.Batch(context.Background(), []Command{{Method: "user_mod"}})
			default:
				_, err = c.Call(context.Background(), Command{Method: method})
			}
			if !errors.Is(err, ErrIncompleteResponse) {
				t.Errorf("missing error accepted: %v", err)
			}
			var unknown *OutcomeUnknownError
			want := method == "user_mod" || method == "batch-write" || method == "batch-envelope-write"
			if errors.As(err, &unknown) != want || (c.Stats().Unknown == 1) != want {
				t.Errorf("classification: %T, %+v", err, c.Stats())
			}
			if c.Stats().ReadRetries != 0 {
				t.Error("malformed answer retried")
			}
		})
	}
}

func TestBatchPingUsesItsCommandContract(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, summary := range []string{`"IPA server version 4.13.4. API version 2.257"`, `null`, `13`, `"invalid"`} {
			t.Run(fmt.Sprintf("mixed=%t/%s", mixed, summary), func(t *testing.T) {
				f, c := loggedIn(t, nil)
				cmds := []Command{{Method: "ping"}}
				items := []json.RawMessage{json.RawMessage(`{"error":null,"summary":` + summary + `}`)}
				if mixed {
					cmds = append(cmds, Command{Method: "user_mod"})
					items = append(items, json.RawMessage(`{"error":null,"result":{"uid":["a"]}}`))
				}
				body, _ := json.Marshal(map[string]any{"error": nil, "result": map[string]any{"count": len(items), "results": items}})
				f.hook = func(w http.ResponseWriter, _ string) bool { _, _ = w.Write(body); return true }
				out, err := c.Batch(context.Background(), cmds)
				if c.Stats().Reads != 1 || c.Stats().Writes != boolCount(mixed) {
					t.Errorf("mixed command counters: %+v", c.Stats())
				}
				valid := strings.HasPrefix(summary, `"IPA server`)
				if valid {
					if err != nil || len(out) != len(cmds) || c.Stats().Unknown != 0 {
						t.Fatalf("legal ping batch: %v, %+v", err, c.Stats())
					}
					return
				}
				if !errors.Is(err, ErrIncompleteResponse) {
					t.Errorf("malformed ping: %v", err)
				}
				var unknown *OutcomeUnknownError
				if errors.As(err, &unknown) != mixed || (c.Stats().Unknown == 1) != mixed {
					t.Errorf("classification: %T, %+v", err, c.Stats())
				}
			})
		}
	}
}

func TestCallPingRequiresItsSummary(t *testing.T) {
	for _, raw := range []string{`{}`, `{"summary":null}`, `{"summary":13}`, `{"summary":"invalid"}`} {
		f, c := loggedIn(t, nil)
		f.hook = func(w http.ResponseWriter, _ string) bool {
			_, _ = io.WriteString(w, `{"error":null,"result":`+raw+`}`)
			return true
		}
		if _, err := c.Call(context.Background(), Command{Method: "ping"}); !errors.Is(err, ErrIncompleteResponse) {
			t.Errorf("invalid ping accepted: %v", err)
		}
	}
}

func TestTransportCannotBypassThePinnedOrigin(t *testing.T) {
	f := newFakeServer(t, testFQDN)
	var calls atomic.Int32
	c := newTestClient(t, f, func(cfg *Config) {
		original := cfg.DialContext
		cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			calls.Add(1)
			return original(ctx, network, addr)
		}
	})
	for _, target := range []string{"http://" + testFQDN + "/ipa/session/login_password", "https://other.example.test/ipa/session/json", "https://" + testFQDN + ":8443/ipa/session/json", "https://user@" + testFQDN + "/ipa/session/json"} {
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(testPassword))
		_, err := c.http.Do(req)
		var ns *notSentError
		if !errors.As(err, &ns) {
			t.Errorf("foreign request not rejected before send: %v", err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+testFQDN+"/ipa/session/json", strings.NewReader(testPassword))
	req.Host = "other.example.test"
	if _, err := c.http.Do(req); err == nil {
		t.Error("foreign Host accepted")
	}
	tr := c.http.Transport.(*originTransport).transport
	if _, err := tr.DialContext(context.Background(), "tcp", testFQDN+":80"); err == nil {
		t.Error("plaintext dial fallback accepted")
	}
	if _, err := tr.DialTLSContext(context.Background(), "tcp", "other.example.test:443"); err == nil {
		t.Error("foreign TLS dial accepted")
	}
	if calls.Load() != 0 {
		t.Errorf("forbidden requests reached supplied dialer %d times", calls.Load())
	}
	if len(f.received()) != 0 {
		t.Error("forbidden requests reached server")
	}
}
