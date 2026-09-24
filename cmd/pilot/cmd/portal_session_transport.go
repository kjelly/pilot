// portal_session_transport.go is State C of the `pilot portal-session`
// ForceCommand dispatcher: `pilot-transport-v1 <target-fqdn>`, a captive,
// opaque SSH transport broker (docs/superpowers/specs/2026-09-23-pilot-
// access-gateway-captive-ssh-transport-spec.md §9). The workstation's own
// OpenSSH runs this as a ProxyCommand over an outer `ssh -T` to the
// gateway; after a fresh authorize this process only ever byte-bridges
// the outer session's stdin/stdout to <resolved-ip>:22. It never parses,
// terminates, or records the inner SSH stream, never starts /usr/bin/ssh,
// and never accepts a caller-chosen port or address.
package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// Fixed protocol constants (spec §9.2) — deliberately not configurable by
// flag, env, or config: the transport is TCP/22 or nothing.
const (
	transportTargetPort     = "22"
	transportDNSTimeout     = 5 * time.Second
	transportDialTimeout    = 5 * time.Second
	transportMaxDialTargets = 3
	// transportStdinGrace bounds how long the bridge waits for the
	// client->target direction after the target side has closed: Go cannot
	// reliably cancel a read blocked on os.Stdin, so waiting unboundedly
	// could pin this ForceCommand process forever (spec §9.3).
	transportStdinGrace = 2 * time.Second
)

// Stable stderr messages (spec §9.6). Everything the transport says goes
// to stderr; stdout carries only target socket bytes.
const (
	transportMsgAccessDenied     = "pilot-transport: access denied"
	transportMsgNotEnabled       = "pilot-transport: transport not enabled for this target"
	transportMsgRecordingPolicy  = "pilot-transport: transport disabled by recording policy"
	transportMsgUnavailable      = "pilot-transport: target unavailable"
	transportMsgTransportError   = "pilot-transport: transport error"
	transportMsgTTYNotAllowed    = "pilot-transport: a TTY is not allowed for transport"
	transportMsgUsage            = "pilot-transport: usage: pilot-transport-v1 <target-fqdn>"
	knownHostsMsgAccessDenied    = "pilot-known-hosts: access denied"
	knownHostsMsgUnavailable     = "pilot-known-hosts: target unavailable"
	knownHostsMsgNoHostKey       = "pilot-known-hosts: no host key published for target"
	knownHostsMsgTTYNotAllowed   = "pilot-known-hosts: a TTY is not allowed for known-hosts"
	knownHostsMsgUsage           = "pilot-known-hosts: usage: pilot-known-hosts-v1 <target-fqdn>"
	transportDenyReasonUnknown   = "transport_not_allowed"
	transportResultRecordingDeny = "recording_incompatible"
)

// transportResolver / transportDialer are the injectable DNS and TCP seams
// (spec §9.2); production uses net.DefaultResolver and a net.Dialer.
type transportResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type transportDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// portalTransportDeps holds everything runPortalTransport touches outside
// its own logic, so tests can drive it without real DNS, sockets, or
// process stdio.
type portalTransportDeps struct {
	client     *portalClient
	resolver   transportResolver
	dialer     transportDialer
	localAddrs func() ([]net.Addr, error)
	stdin      io.Reader
	stdout     io.Writer
	emitter    *sessionaudit.Emitter
	now        func() time.Time
}

// transportStats is one finished bridge's byte counts.
type transportStats struct {
	ClientToTarget int64
	TargetToClient int64
}

// transportRecordingCompatible is an allowlist, not a denylist (spec D8):
// only "" (the unconditional default) and "metadata" may carry an opaque
// transport; terminal_output, terminal_io, and any future mode deny.
func transportRecordingCompatible(mode string) bool {
	return mode == "" || mode == "metadata"
}

// runPortalTransport implements spec §9.1 steps 3-15 (parse and TTY
// checks already happened in the dispatcher). Every return value's
// Error() is one of the stable transport messages above.
func runPortalTransport(ctx context.Context, deps portalTransportDeps, target string) error {
	now := deps.now
	if now == nil {
		now = time.Now
	}
	sessionID := uuid.NewString()

	identity, err := deps.client.Identity(ctx)
	if err != nil {
		return errors.New(transportMsgUnavailable)
	}
	ev := sessionaudit.SessionAuditEvent{
		SessionID: sessionID, User: identity.Username, UID: int(identity.UID), TargetFQDN: target,
		GatewayID: identity.Gateway.ID, GatewayScope: identity.Gateway.Scope,
	}
	emit := func(kind, result string) {
		e := ev
		e.Kind, e.Result = kind, result
		deps.emitter.Emit(e)
	}
	emit(sessionaudit.KindGatewayTransportRequested, "")

	// The transport's own session id: the gateway resolves this target's
	// effective recording mode per host, and for a recorded host it needs a
	// session id to answer at all; the recording allowlist below then
	// refuses the transport (captive-transport spec D8).
	authz, err := deps.client.ConnectAuthorize(ctx, target, sessionID)
	if err != nil {
		emit(sessionaudit.KindGatewayTransportDenied, "authorize_error")
		return errors.New(transportMsgUnavailable)
	}
	if !authz.Allowed {
		emit(sessionaudit.KindGatewayTransportDenied, "authorize_denied")
		return errors.New(transportMsgAccessDenied)
	}
	// From here on only the gateway's canonical target is used — never the
	// raw caller input again (spec §9.1).
	ev.TargetFQDN = authz.Target
	ev.GatewayID, ev.GatewayScope = authz.GatewayID, authz.GatewayScope
	ev.RecordingMode = authz.RecordingMode
	if !authz.TransportAllowed {
		reason := transportDenyReasonUnknown
		if authz.TransportDenyReason != "" {
			reason = "transport_" + authz.TransportDenyReason
		}
		emit(sessionaudit.KindGatewayTransportDenied, reason)
		return errors.New(transportMsgNotEnabled)
	}
	if !transportRecordingCompatible(authz.RecordingMode) {
		emit(sessionaudit.KindGatewayTransportDenied, transportResultRecordingDeny)
		return errors.New(transportMsgRecordingPolicy)
	}

	dnsCtx, cancelDNS := context.WithTimeout(ctx, transportDNSTimeout)
	addrs, err := deps.resolver.LookupIPAddr(dnsCtx, authz.Target)
	cancelDNS()
	if err != nil || len(addrs) == 0 {
		emit(sessionaudit.KindGatewayTransportFailed, "dns")
		return errors.New(transportMsgUnavailable)
	}
	local, err := deps.localAddrs()
	if err != nil {
		// Cannot prove a candidate is not this gateway itself: fail closed.
		emit(sessionaudit.KindGatewayTransportDenied, "no_valid_address")
		return errors.New(transportMsgAccessDenied)
	}
	candidates := filterTransportAddrs(addrs, local)
	if len(candidates) == 0 {
		emit(sessionaudit.KindGatewayTransportDenied, "no_valid_address")
		return errors.New(transportMsgAccessDenied)
	}

	conn, ip, err := dialTransportTarget(ctx, deps.dialer, candidates)
	if err != nil {
		emit(sessionaudit.KindGatewayTransportFailed, "dial")
		return errors.New(transportMsgUnavailable)
	}
	ev.TargetIP = ip.String()
	emit(sessionaudit.KindGatewayTransportConnected, "")

	start := now()
	stats, bridgeErr := bridgeTransport(ctx, deps.stdin, deps.stdout, conn)
	durationMS := now().Sub(start).Milliseconds()
	closed := ev
	closed.Kind = sessionaudit.KindGatewayTransportClosed
	closed.Result = "ok"
	if bridgeErr != nil {
		closed.Result = "error"
	}
	closed.BytesClientToTarget = &stats.ClientToTarget
	closed.BytesTargetToClient = &stats.TargetToClient
	closed.DurationMS = &durationMS
	deps.emitter.Emit(closed)
	if bridgeErr != nil {
		return errors.New(transportMsgTransportError)
	}
	return nil
}

// filterTransportAddrs keeps the resolver's order and drops every address
// the transport must never dial (spec §9.2): unspecified, loopback,
// multicast (incl. interface-local), link-local unicast/multicast,
// zone-scoped addresses, and any address assigned to this gateway. IPv4-
// mapped IPv6 is normalized first so ::ffff:127.0.0.1 is still loopback.
// RFC1918/ULA stay allowed — targets normally live on private networks.
func filterTransportAddrs(addrs []net.IPAddr, local []net.Addr) []net.IP {
	own := make(map[string]struct{}, len(local))
	for _, a := range local {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			own[normalizeTransportIP(ip).String()] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	var out []net.IP
	for _, a := range addrs {
		if a.Zone != "" || a.IP == nil {
			continue
		}
		ip := normalizeTransportIP(a.IP)
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
			ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		key := ip.String()
		if _, isOwn := own[key]; isOwn {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func normalizeTransportIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// dialTransportTarget dials each candidate's exact IP on TCP/22 in order,
// at most transportMaxDialTargets of them. It never dials a hostname and
// never re-resolves (spec §9.2), so the audited IP is the connected IP.
func dialTransportTarget(ctx context.Context, dialer transportDialer, candidates []net.IP) (net.Conn, net.IP, error) {
	var lastErr error
	for i, ip := range candidates {
		if i >= transportMaxDialTargets {
			break
		}
		dialCtx, cancel := context.WithTimeout(ctx, transportDialTimeout)
		conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), transportTargetPort))
		cancel()
		if err == nil {
			return conn, ip, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no dial candidates")
	}
	return nil, nil, lastErr
}

// countingReader / countingWriter count bytes as they flow, so the byte
// totals are right even for a direction that never reaches EOF.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// bridgeTransport copies stdin -> conn and conn -> stdout, byte for byte
// (spec §9.3). stdin EOF half-closes the target socket (CloseWrite) so the
// target can still finish sending; the session ends when the target side
// ends, after at most transportStdinGrace for the client side to drain.
// ctx cancellation (SIGTERM/SIGHUP/SIGINT in production) closes the
// socket, which unblocks both directions. Only a genuine local I/O error
// is reported; EOF, a closed socket, or the client hanging up is a normal
// close.
func bridgeTransport(ctx context.Context, stdin io.Reader, stdout io.Writer, conn net.Conn) (transportStats, error) {
	var up, down atomic.Int64
	upDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, countingReader{r: stdin, n: &up})
		if err == nil {
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		} else {
			_ = conn.Close()
		}
		upDone <- err
	}()
	downDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(countingWriter{w: stdout, n: &down}, conn)
		downDone <- err
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	downErr := <-downDone
	var upErr error
	select {
	case upErr = <-upDone:
	case <-time.After(transportStdinGrace):
	}
	_ = conn.Close()

	stats := transportStats{ClientToTarget: up.Load(), TargetToClient: down.Load()}
	if ctx.Err() != nil {
		return stats, nil
	}
	if isTransportLocalIOError(downErr) {
		return stats, downErr
	}
	if isTransportLocalIOError(upErr) {
		return stats, upErr
	}
	return stats, nil
}

// isTransportLocalIOError reports whether err is a real local I/O failure
// rather than an ordinary end of session (EOF, the socket already closed by
// the other direction, or the client/target hanging up).
func isTransportLocalIOError(err error) bool {
	switch {
	case err == nil,
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ECONNRESET):
		return false
	}
	return true
}
