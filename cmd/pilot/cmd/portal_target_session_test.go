package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/muesli/cancelreader"
	"golang.org/x/sys/unix"

	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/sessionaudit"
	"github.com/kjelly/pilot/internal/sessionrecording"
)

const testSessionID = "0d33c638-83fa-4d77-9811-a97a7a7af1d5"

var hostOutputPolicy = freeipaaccess.HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}

// fakeStore stands in for pilot-session-store over real TLS and records
// every ingest request.
type fakeStore struct {
	mu        sync.Mutex
	startCode int
	startBody string
	requests  []fakeStoreRequest
}

type fakeStoreRequest struct {
	path string
	body []byte
}

func (s *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, fakeStoreRequest{path: r.URL.Path, body: body})
	code, msg := http.StatusOK, ""
	if strings.HasSuffix(r.URL.Path, "/start") && s.startCode != 0 {
		code, msg = s.startCode, s.startBody
	}
	s.mu.Unlock()
	w.WriteHeader(code)
	_, _ = io.WriteString(w, msg)
}

func (s *fakeStore) snapshot() []fakeStoreRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeStoreRequest(nil), s.requests...)
}

func (s *fakeStore) finishes(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range s.snapshot() {
		if strings.HasSuffix(r.path, "/finish") {
			var m map[string]any
			if err := json.Unmarshal(r.body, &m); err != nil {
				t.Fatalf("decode finish: %v", err)
			}
			out = append(out, m)
		}
	}
	return out
}

func (s *fakeStore) events(t *testing.T) []sessionrecording.TerminalEvent {
	t.Helper()
	var out []sessionrecording.TerminalEvent
	for _, r := range s.snapshot() {
		if strings.HasSuffix(r.path, "/events") {
			var req struct {
				Events []sessionrecording.TerminalEvent `json:"events"`
			}
			if err := json.Unmarshal(r.body, &req); err != nil {
				t.Fatalf("decode events: %v", err)
			}
			out = append(out, req.Events...)
		}
	}
	return out
}

// startFakeStore returns the store, its URL and a CA file trusting it.
func startFakeStore(t *testing.T) (*fakeStore, string, string) {
	t.Helper()
	store := &fakeStore{}
	srv := httptest.NewTLSServer(store)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return store, srv.URL, ca
}

func storeRecordingPolicy(t *testing.T, url, ca string) gatewayapi.RecordingPolicy {
	t.Helper()
	signer, err := ingesttoken.NewSigner([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return gatewayapi.RecordingPolicy{
		FailurePolicy: "fail_closed", QueueEvents: 64, FlushIntervalMS: 20, FailureGraceMS: 2000,
		MaxSessionDuration: time.Hour, SessionStoreURL: url, SessionStoreCAFile: ca, Signer: signer,
	}
}

// fakeTransport stands in for the two-phase ControlMaster flow; Phase B
// runs `sh -c script` on a real pty instead of ssh.
type fakeTransport struct {
	mu            sync.Mutex
	script        string
	authErr       error
	startErr      error
	authenticated bool
	started       bool
	size          sessionrecording.Winsize
}

func (f *fakeTransport) authenticate(string, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authenticated = true
	return f.authErr
}

func (f *fakeTransport) startRecorded(_, _ string, size sessionrecording.Winsize) (*os.File, *exec.Cmd, error) {
	f.mu.Lock()
	f.started, f.size = true, size
	startErr, script := f.startErr, f.script
	f.mu.Unlock()
	if startErr != nil {
		return nil, nil, startErr
	}
	cmd := exec.Command("sh", "-c", script)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(size.Rows), Cols: uint16(size.Cols)})
	return ptmx, cmd, err
}

func (f *fakeTransport) closeMaster(string, string) {}
func (f *fakeTransport) cleanup()                   {}

func (f *fakeTransport) state() (authenticated, started bool, size sessionrecording.Winsize) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authenticated, f.started, f.size
}

// withRecordedTransport installs ft and returns how many transports the
// connect core created.
func withRecordedTransport(t *testing.T, ft *fakeTransport) *atomic.Int32 {
	t.Helper()
	var created atomic.Int32
	old := newRecordedTransport
	newRecordedTransport = func() (recordedTransport, error) {
		created.Add(1)
		return ft, nil
	}
	t.Cleanup(func() { newRecordedTransport = old })
	return &created
}

func withNoSSHLauncher(t *testing.T) *atomic.Bool {
	t.Helper()
	var launched atomic.Bool
	withSSHLauncher(t, func(*exec.Cmd) error {
		launched.Store(true)
		return nil
	})
	return &launched
}

// blockingInput is an idle terminal's input: Read blocks until Cancel.
type blockingInput struct {
	once     sync.Once
	ch       chan struct{}
	canceled atomic.Bool
	active   atomic.Int32
}

func newBlockingInput() *blockingInput { return &blockingInput{ch: make(chan struct{})} }

func (b *blockingInput) Read([]byte) (int, error) {
	b.active.Add(1)
	defer b.active.Add(-1)
	<-b.ch
	return 0, cancelreader.ErrCanceled
}

func (b *blockingInput) Cancel() bool {
	b.canceled.Store(true)
	b.once.Do(func() { close(b.ch) })
	return true
}

func (b *blockingInput) Close() error { return nil }

// lockedBuffer is a goroutine-safe audit sink.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	b.buf.WriteByte('\n')
	return len(p), nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) events(t *testing.T) []sessionaudit.SessionAuditEvent {
	t.Helper()
	var out []sessionaudit.SessionAuditEvent
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var ev sessionaudit.SessionAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

type testSession struct {
	deps   portalSessionDeps
	notice *bytes.Buffer
	stdout *lockedBuffer
	audit  *lockedBuffer
	input  *blockingInput
	creds  *fakePortalCredentialSession
}

func newTestSession(client *portalClient) *testSession {
	s := &testSession{notice: &bytes.Buffer{}, stdout: &lockedBuffer{}, audit: &lockedBuffer{}, input: newBlockingInput(),
		creds: &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-test/krb5cc"}}
	s.deps = portalSessionDeps{
		Client: client, Credentials: s.creds, Emitter: sessionaudit.NewWriterEmitter("test", s.audit),
		SSHConfigPath: "/etc/pilot/ssh_config", Stdin: s.input, Stdout: s.stdout, Notice: s.notice,
	}
	return s
}

func recordingGateway(t *testing.T, policy *freeipaaccess.HostRecordingPolicy) (*portalClient, *fakeStore) {
	t.Helper()
	store, url, ca := startFakeStore(t)
	provider := &fakeGatewayProvider{username: currentOSUsername(t), recording: policy}
	return startFakeGatewayWithProvider(t, provider, storeRecordingPolicy(t, url, ca)), store
}

func TestPortalTargetSession_MetadataPlainPathUnchanged(t *testing.T) {
	client, store := recordingGateway(t, nil)
	created := withRecordedTransport(t, &fakeTransport{})
	var launched *exec.Cmd
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = cmd
		return nil
	})
	s := newTestSession(client)
	if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
		t.Fatalf("runPortalTargetSession: %v", err)
	}
	if launched == nil || strings.Join(launched.Args, " ") != sshBinaryPath+" -F /etc/pilot/ssh_config gpu-a.example.com" {
		t.Fatalf("plain ssh = %v, want the fixed argv", launched)
	}
	if created.Load() != 0 || s.notice.Len() != 0 || len(store.snapshot()) != 0 {
		t.Fatalf("metadata session touched the recorded path: transports=%d notice=%q store=%d", created.Load(), s.notice.String(), len(store.snapshot()))
	}
}

// TestConnectToHost_TerminalModeUsesRecordedPath locks AG50: the
// interactive Portal Connect records a host whose policy asks for it,
// through the same recorded path as the Directory handoff.
func TestConnectToHost_TerminalModeUsesRecordedPath(t *testing.T) {
	client, store := recordingGateway(t, &hostOutputPolicy)
	ft := &fakeTransport{script: "printf 'hello-from-target\\n'"}
	withRecordedTransport(t, ft)
	launched := withNoSSHLauncher(t)
	stdout, stderr := withPortalTerminal(t)
	input := newBlockingInput()
	withPortalInputReader(t, input)

	p := &promptAutomation{}
	withPromptAutomation(t, p, func() {
		if err := connectToHost(context.Background(), client, &fakePortalCredentialSession{cache: "FILE:/tmp/cc"}, "/etc/pilot/ssh_config", "gpu-a.example.com"); err != nil {
			t.Fatalf("connectToHost: %v", err)
		}
	})
	if p.err != nil {
		t.Fatalf("a clean recorded session showed a prompt: %v", p.err)
	}
	if launched.Load() {
		t.Fatal("the plain unrecorded ssh path ran for a terminal_output host")
	}
	if auth, started, _ := ft.state(); !auth || !started {
		t.Fatalf("recorded transport authenticated=%v started=%v", auth, started)
	}
	finishes := store.finishes(t)
	if len(finishes) != 1 || finishes[0]["complete"] != true {
		t.Fatalf("store finishes = %v, want one complete finish", finishes)
	}
	var output strings.Builder
	for _, ev := range store.events(t) {
		if ev.Stream == sessionrecording.StreamTTYOutput {
			output.WriteString(ev.DataBase64)
		}
	}
	if output.Len() == 0 || !strings.Contains(stdout.String(), "hello-from-target") {
		t.Fatalf("recorded output events=%q stdout=%q", output.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "This SSH session is recorded by Pilot (terminal output). Session ID: ") {
		t.Fatalf("notice = %q", stderr.String())
	}
}

// TestPortalTargetSession_StoreStartFailureNoSSH locks AG51: when the store
// refuses the session start, no ssh process runs, Phase A included.
func TestPortalTargetSession_StoreStartFailureNoSSH(t *testing.T) {
	client, store := recordingGateway(t, &hostOutputPolicy)
	store.startCode, store.startBody = http.StatusUnauthorized, `{"error":"start_window_closed"}`
	created := withRecordedTransport(t, &fakeTransport{script: "true"})
	launched := withNoSSHLauncher(t)
	s := newTestSession(client)

	err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com")
	var ce *portalConnectError
	if !errors.As(err, &ce) || ce.stage != portalStageRecording || !strings.Contains(ce.msg, "connect again") {
		t.Fatalf("err = %v, want a recording-stage error asking to reconnect", err)
	}
	if created.Load() != 0 || launched.Load() {
		t.Fatalf("store start failed but ssh ran: transports=%d plain=%v", created.Load(), launched.Load())
	}
	if reqs := store.snapshot(); len(reqs) != 1 || !strings.HasSuffix(reqs[0].path, "/start") {
		t.Fatalf("store requests = %d, want only the refused start", len(reqs))
	}
	if !strings.Contains(s.audit.String(), `"kind":"recording_failed"`) {
		t.Fatalf("no recording_failed audit event: %s", s.audit.String())
	}
}

// TestPortalTargetSession_NoLocalRecordingFile locks AG52: a recorded
// session leaves nothing on the gateway's disk; the former FileSink path
// is gone.
func TestPortalTargetSession_NoLocalRecordingFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	marker := "marker-" + uuid.NewString()
	client, _ := recordingGateway(t, &hostOutputPolicy)
	withRecordedTransport(t, &fakeTransport{script: "printf '" + marker + "\\n'"})
	withNoSSHLauncher(t)
	s := newTestSession(client)
	if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
		t.Fatalf("runPortalTargetSession: %v", err)
	}
	if _, err := os.Stat(filepath.Join(portalKerberosRuntimeBase(os.Getuid()), "pilot-session-recordings", testSessionID+".ndjson")); !os.IsNotExist(err) {
		t.Fatalf("the former local recording file exists (stat err %v)", err)
	}
	for _, root := range []string{tmp, portalKerberosRuntimeBase(os.Getuid())} {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if strings.Contains(d.Name(), testSessionID) {
				t.Errorf("found a file named after the session: %s", path)
			}
			if root == tmp && !d.IsDir() {
				if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte(marker)) {
					t.Errorf("recorded output was written to %s", path)
				}
			}
			return nil
		})
	}
}

// TestPortalTargetSession_RecordingNotice locks AG54: terminal modes print
// the pre-connect notice with the session id; metadata prints nothing.
func TestPortalTargetSession_RecordingNotice(t *testing.T) {
	t.Run("terminal_output", func(t *testing.T) {
		client, _ := recordingGateway(t, &hostOutputPolicy)
		withRecordedTransport(t, &fakeTransport{script: "true"})
		withNoSSHLauncher(t)
		s := newTestSession(client)
		if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
			t.Fatal(err)
		}
		want := "This SSH session is recorded by Pilot (terminal output). Session ID: " + testSessionID + "\n"
		if s.notice.String() != want {
			t.Fatalf("notice = %q, want %q", s.notice.String(), want)
		}
	})
	t.Run("terminal_io", func(t *testing.T) {
		store, url, ca := startFakeStore(t)
		_ = store
		policy := storeRecordingPolicy(t, url, ca)
		policy.DefaultMode = "terminal_io"
		client := startFakeGatewayWithProvider(t, &fakeGatewayProvider{username: currentOSUsername(t)}, policy)
		withRecordedTransport(t, &fakeTransport{script: "true"})
		withNoSSHLauncher(t)
		s := newTestSession(client)
		if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
			t.Fatal(err)
		}
		want := "This SSH session is recorded by Pilot (terminal output and input; typed input is stored as redacted byte counts). Session ID: " + testSessionID + "\n"
		if s.notice.String() != want {
			t.Fatalf("notice = %q, want %q", s.notice.String(), want)
		}
	})
	t.Run("metadata", func(t *testing.T) {
		client, _ := recordingGateway(t, nil)
		withSSHLauncher(t, func(*exec.Cmd) error { return nil })
		s := newTestSession(client)
		if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
			t.Fatal(err)
		}
		if s.notice.Len() != 0 {
			t.Fatalf("metadata session printed a notice: %q", s.notice.String())
		}
	})
}

func TestPortalTargetSession_DenyReasonMessages(t *testing.T) {
	store, url, ca := startFakeStore(t)
	_ = store
	withStore := storeRecordingPolicy(t, url, ca)
	noStore := gatewayapi.RecordingPolicy{FailurePolicy: "fail_closed"}
	invalid := freeipaaccess.HostRecordingPolicy{Present: true, Reason: "duplicate"}
	cases := map[string]struct {
		provider *fakeGatewayProvider
		policy   gatewayapi.RecordingPolicy
		sid      string
		want     string
	}{
		"policy unavailable": {&fakeGatewayProvider{hostShowErr: errors.New("boom")}, withStore, testSessionID, "Connection not started: this host's recording policy could not be verified."},
		"policy invalid":     {&fakeGatewayProvider{recording: &invalid}, withStore, testSessionID, "Connection not started: this host's recording policy is misconfigured. Contact an administrator."},
		"backend missing":    {&fakeGatewayProvider{recording: &hostOutputPolicy}, noStore, testSessionID, "Connection not started: session recording is required for this host but the recording service is not configured."},
		"session id invalid": {&fakeGatewayProvider{recording: &hostOutputPolicy}, withStore, "", "Connection not started: internal session id error."},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.provider.username = currentOSUsername(t)
			client := startFakeGatewayWithProvider(t, c.provider, c.policy)
			created := withRecordedTransport(t, &fakeTransport{})
			launched := withNoSSHLauncher(t)
			s := newTestSession(client)
			err := runPortalTargetSession(context.Background(), s.deps, c.sid, "gpu-a.example.com")
			if err == nil || !strings.Contains(err.Error(), c.want) || portalConnectPromptMessage(err) != c.want {
				t.Fatalf("err = %v, prompt %q; want %q", err, portalConnectPromptMessage(err), c.want)
			}
			if len(s.creds.users) != 0 || created.Load() != 0 || launched.Load() {
				t.Fatal("a recording deny still asked for credentials or started ssh")
			}
		})
	}
}

// TestPortalTargetSession_EnsureAfterAuthorize: a denied target never asks
// for Kerberos credentials, and a credential failure happens before any
// recording notice or store request.
func TestPortalTargetSession_EnsureAfterAuthorize(t *testing.T) {
	client, store := recordingGateway(t, &hostOutputPolicy)
	withNoSSHLauncher(t)
	s := newTestSession(client)
	if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "not-in-scope.example.com"); err == nil {
		t.Fatal("out-of-scope target allowed")
	}
	if len(s.creds.users) != 0 {
		t.Fatalf("credentials requested for a denied target: %v", s.creds.users)
	}

	s = newTestSession(client)
	s.creds.err = errors.New("ticket unavailable")
	err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com")
	var ce *portalConnectError
	if !errors.As(err, &ce) || ce.stage != portalStageCredentials {
		t.Fatalf("err = %v, want a credentials-stage error", err)
	}
	if s.notice.Len() != 0 || len(store.snapshot()) != 0 {
		t.Fatalf("credential failure after notice/store start: notice=%q store=%d", s.notice.String(), len(store.snapshot()))
	}
}

// TestPortalTargetSession_FailureAfterStartFinishesIncomplete: once the
// store accepted the session, a Phase A or Phase B failure still sends an
// incomplete finish.
func TestPortalTargetSession_FailureAfterStartFinishesIncomplete(t *testing.T) {
	for name, ft := range map[string]*fakeTransport{
		"phase A": {authErr: errors.New("pre-auth ControlMaster failed")},
		"phase B": {startErr: errors.New("start recorded session: boom")},
	} {
		t.Run(name, func(t *testing.T) {
			client, store := recordingGateway(t, &hostOutputPolicy)
			withRecordedTransport(t, ft)
			withNoSSHLauncher(t)
			s := newTestSession(client)
			err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com")
			var ce *portalConnectError
			if !errors.As(err, &ce) || ce.stage != portalStageSSH {
				t.Fatalf("err = %v, want an ssh-stage error", err)
			}
			finishes := store.finishes(t)
			if len(finishes) != 1 || finishes[0]["complete"] != false || finishes[0]["last_seq"] != float64(0) {
				t.Fatalf("finishes = %v, want one incomplete finish with last_seq 0", finishes)
			}
			if !strings.Contains(s.audit.String(), `"kind":"target_connect_failed"`) {
				t.Fatalf("no target_connect_failed audit event: %s", s.audit.String())
			}
		})
	}
}

// TestPortalTargetSession_AuditEventsCarrySessionFields locks per-host
// recording spec §22 for both connect paths.
func TestPortalTargetSession_AuditEventsCarrySessionFields(t *testing.T) {
	client, _ := recordingGateway(t, &hostOutputPolicy)
	withRecordedTransport(t, &fakeTransport{script: "true"})
	withNoSSHLauncher(t)
	s := newTestSession(client)
	if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ev := range s.audit.events(t) {
		seen[ev.Kind] = true
		if ev.SessionID != testSessionID || ev.User != currentOSUsername(t) || ev.TargetFQDN != "gpu-a.example.com" ||
			ev.GatewayID != "gpu-01" || ev.GatewayScope != "gpu" || ev.RecordingMode != "terminal_output" || ev.RecordingPolicySource != "host" {
			t.Errorf("%s event missing session fields: %+v", ev.Kind, ev)
		}
	}
	for _, kind := range []string{sessionaudit.KindGatewayAuthorizeAllowed, sessionaudit.KindTargetConnectStarted, sessionaudit.KindRecordingStarted, sessionaudit.KindSessionEnded} {
		if !seen[kind] {
			t.Errorf("no %s event", kind)
		}
	}

	s = newTestSession(client)
	_ = runPortalTargetSession(context.Background(), s.deps, "", "gpu-a.example.com")
	for _, ev := range s.audit.events(t) {
		if ev.Kind == sessionaudit.KindGatewayAuthorizeDenied && ev.Result != gatewayapi.DenyReasonRecordingSessionID {
			t.Fatalf("denied Result = %q, want only the deny reason", ev.Result)
		}
	}
}

// TestRunPortalOneShotConnect_RecordingEnabledSkipsPlainPath: an effective
// terminal mode takes the recorded path end to end, never the plain ssh.
func TestRunPortalOneShotConnect_RecordingEnabledSkipsPlainPath(t *testing.T) {
	store, url, ca := startFakeStore(t)
	policy := storeRecordingPolicy(t, url, ca)
	policy.DefaultMode = "terminal_io"
	client := startFakeGatewayWithProvider(t, &fakeGatewayProvider{username: currentOSUsername(t)}, policy)
	ft := &fakeTransport{script: "true"}
	withRecordedTransport(t, ft)
	launched := withNoSSHLauncher(t)
	s := newTestSession(client)
	if err := runPortalTargetSession(context.Background(), s.deps, testSessionID, "gpu-a.example.com"); err != nil {
		t.Fatalf("runPortalTargetSession: %v", err)
	}
	if launched.Load() {
		t.Fatal("sshLauncher (the plain, unrecorded path) was invoked despite an effective terminal_io mode")
	}
	if auth, started, size := ft.state(); !auth || !started || size != (sessionrecording.Winsize{Rows: 24, Cols: 80}) {
		t.Fatalf("recorded transport = auth %v started %v size %+v", auth, started, size)
	}
	if f := store.finishes(t); len(f) != 1 {
		t.Fatalf("store finishes = %v", f)
	}
	if evs := store.events(t); len(evs) == 0 || evs[0].Seq != 1 || evs[0].Stream != sessionrecording.StreamResize || evs[0].Rows != 24 || evs[0].Cols != 80 {
		t.Fatalf("first recorded event = %+v, want the initial 80x24 resize", evs)
	}
}

// withPortalTerminal points the interactive Portal at a pipe for stdin and
// buffers for stdout/stderr.
func withPortalTerminal(t *testing.T) (*lockedBuffer, *lockedBuffer) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	stdout, stderr := &lockedBuffer{}, &lockedBuffer{}
	oldIn, oldOut, oldErr, oldEmitter := portalStdin, portalStdout, portalStderr, portalAuditEmitter
	portalStdin, portalStdout, portalStderr = r, stdout, stderr
	portalAuditEmitter = func() *sessionaudit.Emitter { return sessionaudit.NewWriterEmitter("test", &lockedBuffer{}) }
	t.Cleanup(func() {
		portalStdin, portalStdout, portalStderr, portalAuditEmitter = oldIn, oldOut, oldErr, oldEmitter
	})
	return stdout, stderr
}

func withPortalInputReader(t *testing.T, in *blockingInput) {
	t.Helper()
	old := newPortalInputReader
	newPortalInputReader = func(*os.File) (cancelreader.CancelReader, error) { return in, nil }
	t.Cleanup(func() { newPortalInputReader = old })
}

// TestConnectToHost_NoStdinReaderLeftAfterRecordedSession (F28): once a
// recorded Connect returns, its input reader has been canceled and nothing
// is still reading the terminal.
func TestConnectToHost_NoStdinReaderLeftAfterRecordedSession(t *testing.T) {
	client, _ := recordingGateway(t, &hostOutputPolicy)
	withRecordedTransport(t, &fakeTransport{script: "sleep 0.1"})
	withNoSSHLauncher(t)
	withPortalTerminal(t)
	input := newBlockingInput()
	withPortalInputReader(t, input)
	withPromptAutomation(t, &promptAutomation{}, func() {
		_ = connectToHost(context.Background(), client, &fakePortalCredentialSession{cache: "FILE:/tmp/cc"}, "/etc/pilot/ssh_config", "gpu-a.example.com")
	})
	if !input.canceled.Load() {
		t.Fatal("the recorded session's input reader was never canceled")
	}
	if n := input.active.Load(); n != 0 {
		t.Fatalf("%d goroutine(s) still reading stdin after Connect returned", n)
	}
}

// TestConnectToHost_RecordedSessionPTY runs a recorded Connect on a real
// outer pty: raw mode during the session, the original termios afterwards,
// and the next byte typed reaches the caller, not a leftover goroutine.
func TestConnectToHost_RecordedSessionPTY(t *testing.T) {
	client, _ := recordingGateway(t, &hostOutputPolicy)
	withRecordedTransport(t, &fakeTransport{script: "sleep 0.4"})
	withNoSSHLauncher(t)
	withPortalTerminal(t)

	ptm, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	t.Cleanup(func() { _ = ptm.Close(); _ = pts.Close() })
	go func() { _, _ = io.Copy(io.Discard, ptm) }() // drain echo and output
	before, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	portalStdin = pts

	var sawRaw atomic.Bool
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cur, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS); err == nil && cur.Lflag&unix.ICANON == 0 {
				sawRaw.Store(true)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	withPromptAutomation(t, &promptAutomation{}, func() {
		_ = connectToHost(context.Background(), client, &fakePortalCredentialSession{cache: "FILE:/tmp/cc"}, "/etc/pilot/ssh_config", "gpu-a.example.com")
	})
	close(stop)
	if !sawRaw.Load() {
		t.Fatal("the outer terminal was never in raw mode during the recorded session")
	}
	after, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag || after.Oflag != before.Oflag {
		t.Fatalf("termios not restored: before %+v after %+v", before, after)
	}

	if _, err := ptm.Write([]byte("next\n")); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := pts.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case line := <-got:
		if line != "next\n" {
			t.Fatalf("caller read %q, want the typed line", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the typed line never reached the caller: a leftover goroutine consumed it")
	}
}
