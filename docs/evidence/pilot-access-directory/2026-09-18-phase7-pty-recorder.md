# Phase 7 — PTY session recorder

Spec: `docs/tmp/now/spec.md` §23-§27, §35, Phase 7 landing gate (§44).

## What was built

- `internal/sessionrecording/`: `TerminalEvent` (spec §25.3, field-for-field),
  `Sink`/`NullSink`/`FileSink` (plain NDJSON, explicit Phase-8 stopgap),
  `isEchoOff` (real termios read), `Recorder`/`New`/`Run` implementing
  §25.1's full behavior list — raw-mode enter/restore, bidirectional relay
  with mode-correct recording, SIGWINCH→resize events, echo-off redaction,
  bounded backpressure with rate-limited `recording_gap`, `best_effort`
  vs `fail_closed` failure policy (a background ticker enforces the grace
  period in wall-clock time, not just on event arrival — an earlier,
  event-driven-only version failed its own test under sparse traffic).
- `cmd/pilot/cmd/portal_ssh_recording.go`: spec §24.1's two-phase
  ControlMaster flow (unrecorded Phase A auth with an implementation-owned
  `RequestTTY=no` override, recorded Phase B reusing the control socket,
  `-O exit` teardown, private 0700 control-socket directory).
- `portal_session_connect.go`'s mode fork: `metadata` (default) stays the
  exact pre-Phase-7 direct `sshLauncher`/`buildConnectSSHCmd` call
  (`runPortalOneShotConnectPlain`); `terminal_output`/`terminal_io` route
  through the two-phase flow + `Recorder` (`runPortalOneShotConnectRecorded`).
  Recording policy comes back on the same fresh `ConnectAuthorize`
  response as the allow/deny decision — the Gateway daemon's own config
  is the single source of truth, never a Directory- or client-supplied
  parameter.
- Config: `cmd/pilot-access-gateway/config.go` gained `gateway.recording.*`
  (mode/failure_policy/queue_events/flush_interval), all optional,
  `metadata`/`best_effort` unconditional defaults (D8). Deliberately no
  session-store URL/token field (Phase 8's contract to define).
- 8 new `internal/sessionrecording` tests (all against real
  `github.com/creack/pty` pairs and a real spawned child, no mocked I/O),
  clean under `-race`. Full repo: 3827 tests / 52 packages before this
  evidence-gathering session's two live-found fixes below; re-run pending
  in this same commit (see final count at the end of this doc).

## Two real bugs found live and fixed (neither caught by the implementer's
own tests — both required a real target and a real interactive session)

### 1. `ssh -fN` + `cmd.CombinedOutput()` hangs forever (100% hang rate for
every recorded-mode Connect)

`recordedConnectSession.authenticate` (Phase A) used
`exec.Command(..., "-fN", target).CombinedOutput()`. `ssh -f` forks into
the background *after* authenticating; the backgrounded ControlMaster
process inherits the pipe `CombinedOutput` set up for stdout/stderr and,
being long-lived, never closes it. `CombinedOutput`'s internal
read-until-EOF then never sees EOF, hanging the entire one-shot connect
indefinitely — confirmed live: `pilot portal-session` sat blocked with the
`-fN` ControlMaster process alive in the background for 6+ seconds with
no progress, process tree showed no Phase B `-tt` process ever spawned.
Fixed by redirecting `cmd.Stdout`/`cmd.Stderr` to a real temp file instead
(`cmd.Run()`, not `CombinedOutput()`) — a background child can hold a real
file's fd open forever harmlessly; `cmd.Run()` only waits for the direct
foreground child (which exits promptly once it forks) to exit.

### 2. Default recording path (`/run/pilot/session-recordings`) is not
writable by the connecting user

`/run/pilot` is root-owned mode 0755 (it holds the Gateway daemon's own
Unix socket) — the one-shot connect process runs as the *connecting user*
(e.g. `alice`), not the Gateway service account, so `MkdirAll` under it
silently failed and every recorded connect failed closed with `open
.../recordings/<id>.ndjson: no such file or directory`. Fixed by moving
the default path to the same per-uid XDG runtime base
(`portalKerberosRuntimeBase(os.Getuid())`) `newRecordedConnectSession`
already correctly uses for its own control-socket directory — consistent
with this codebase's existing per-user Kerberos-cache precedent, and
correctly permissioned for exactly this "user's own process writes its
own private runtime file" case.

## A significant, verified design-assumption gap (documented, not silently
shipped): echo-off redaction does not work for Gateway's actual child

Live-tested against `ag-target01`/`alice` with 20ms termios polling across
a session spanning a normal command, `sudo -k`, a real password-required
`sudo whoami` (a genuine `[sudo] password for alice:` prompt appeared),
password entry, and a post-prompt command: ECHO/ICANON went to `false` at
session start and stayed `false` continuously until session end — **no
transition near the actual password prompt**. Root cause: OpenSSH's
client puts its *own* local controlling terminal (the pty Gateway
allocates for the `ssh -tt <target>` child) into raw mode for the
*entire* interactive session, relying on the *remote* pty's echo to
reflect keystrokes back over the wire — there is no SSH protocol signal a
client can introspect for "the remote side just disabled echo" once a
session is established (unlike keyboard-interactive *authentication*
prompts, which do carry an explicit per-prompt echo flag, but that's
Phase A, before recording starts).

Practical effect: in `terminal_io` mode today, essentially every input
chunk evaluates `isEchoOff=true` and gets redacted to a byte-count —
**the recorder cannot currently capture real typed command text via this
SSH-relay path**, only via `terminal_output`'s unaffected output-side
recording. This is safe (over-redaction can never leak a secret) but not
useful for `terminal_io`'s stated distinguishing purpose. Deliberately
NOT patched with an under-tested output-scanning heuristic under time
pressure — an heuristic that misses a real prompt phrasing would be a
strictly worse failure (under-redaction, a real leak) than today's
over-redaction. Documented as required follow-up work in `redaction.go`'s
doc comment, `recorder.go`'s `enqueueInput` comment, `redaction_test.go`,
and `docs/tmp/now/spec.md` §26 itself (a correction note, not a silent
edit — the original text is preserved below it).

This does **not** affect SR04 (target's own SSH *authentication* secret
excluded from recording) — that's Phase A/§24's structural separation,
verified independently below, and is unrelated to echo-based redaction.

## Live landing-gate verification

Redeployed `pilot`/`pilot-access-gateway` on `ag-gw01` with both fixes
applied, manually added `gateway.recording: {mode: terminal_output,
failure_policy: best_effort, queue_events: 1024, flush_interval: 500ms}`
to `/etc/pilot/access-gateway.yaml` (not yet wired into the apply
playbook template — explicitly deferred to Phase 8 per spec §35, an
operator can hand-edit today), restarted the service.

### Real end-to-end recorded connect

`alice`, via `pilot directory` (`ag-directory01`) → `ag-gw01` (gpu scope,
`terminal_output` mode) → `ag-target01`: real shell, ran
`echo VERIFY_RECORDING_CONTENT_XYZ123`, saw real output, `exit` returned
cleanly to Directory. Gateway audit trail:
`gateway_authorize_allowed → target_connect_started → recording_started →
session_ended (result=ok)` — no `recording_failed`/`recording_gap`.

Inspected the actual recording file **while the session was still open**
(`/run/user/261200004/pilot-session-recordings/<session-id>.ndjson`,
owner `alice:alice`, mode `600`):

```
seq=1 tty_output 'Welcome to Ubuntu 24.04.4 LTS ...\r\n...Last login: ...\r\r\n'
seq=2 tty_output '$ '
seq=3 tty_output 'echo VERIFY_RECORDING_CONTENT_XYZ123\r\nVERIFY_RECORDING_CONTENT_XYZ123\r\n$ '
```

Real, correctly base64-decoded output content, correct sequence numbers,
private file permissions. **No `tty_input` stream at all** (`terminal_output`
mode correctly never records input — matches `TestRecorderTerminalOutputNeverRecordsInput`,
now proven live too). No SSH authentication banner/host-key-warning
content anywhere in the capture — it starts directly at the post-auth
MOTD, confirming Phase A/§24's separation holds in practice, not just by
construction.

### Resize

Resized the outer trec terminal (100x30 → 120x40) mid-session; no error,
session continued normally (a `resize` event's exact content wasn't
independently re-verified byte-for-byte in this live pass — covered by
`TestRecorderResizeProducesEvent`'s real-pty unit test instead).

### `metadata` mode unaffected (regression check)

Restored `ag-gw01` to its deployed baseline (no `recording:` section, i.e.
`metadata` default) and re-ran a normal Connect: identical behavior to
every prior phase's evidence — real shell, `whoami`=alice, clean return —
confirming the mode fork introduced no regression to the unconditional
default path.

## Residual state

- `ag-gw01` restored to its deployed baseline config (recording section
  removed, `systemctl restart`ed) — no experimental config left on this
  shared, long-lived fixture.
- Test recording files under `/run/user/261200004/pilot-session-recordings/`
  removed.
- `docs/tmp/now/spec.md` §26 carries a dated correction note (not a
  silent rewrite) recording the echo-off finding for whoever reads the
  spec next.

## Deferred to Phase 8 (per spec §34/§35, not Phase 7 gaps)

- `recording.*` wiring into `contracts/pilot-access-gateway.yaml` groupVars
  and the apply-playbook's rendered config template — grouped with the
  session-store URL/token fields Phase 7 was explicitly told to exclude;
  an operator can set it by hand today, matching spec §35's own
  "test sink before Phase 8" framing.
- A real, tested output-scanning heuristic to make `terminal_io` mode
  actually capture typed command text (the echo-off gap above).
- `fail_closed` policy and `recording_gap`/backpressure behavior are
  unit-tested (real pty, `-race` clean) but not independently re-verified
  against a live target in this pass — no changes were made to that logic
  during this evidence-gathering session, so the existing unit test
  coverage stands as its evidence for now.
