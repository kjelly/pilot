// portal_session.go is the Go-side handler for sshd's
// `ForceCommand /usr/local/libexec/pilot-session` (docs/tmp/now/spec.md
// §16/§17/D7). The libexec entry point itself is a tiny shell script that
// unsets a handful of inherited env vars and execs `pilot portal-session`
// — it NEVER references $SSH_ORIGINAL_COMMAND itself. This command reads
// it directly via os.Getenv, in Go, and strictly parses it here: D7's
// absolute prohibition ("SSH_ORIGINAL_COMMAND 永遠不得交給 shell") is about
// never handing that string to `sh -c`/`bash -c`/`eval`; reading an
// inherited environment variable in a Go process is not shell
// interpretation, and no shell is ever invoked with it as input anywhere
// in this file.
//
// Before this file existed, the wrapper unconditionally exec'd `pilot
// portal` regardless of $SSH_ORIGINAL_COMMAND — harmless (never a shell,
// never ran the requested command) but also never rejected a malformed or
// malicious command, it just silently fell through to the interactive
// TUI. spec.md §17's "anything else -> deny" is a deliberate behavior
// change this file introduces, not a preexisting property.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// portalConnectCommandPrefix is the exact, fixed grammar spec.md §16/§17.1
// requires: SSH_ORIGINAL_COMMAND is either empty (-> pilot portal) or
// exactly "pilot-connect <session-id> <target-fqdn>" (-> one-shot
// connect) — never interpreted as a shell command line.
const portalConnectCommandPrefix = "pilot-connect "

// portalFQDNLabelRe / portalIPv4LikeRe mirror directory_session.go's
// parseDirectoryConnectFQDN validation rules exactly (same spec.md §17.1
// grammar, applied on the Gateway side of the same handoff). Duplicated
// rather than shared: the two parsers belong to different ends of the
// protocol and this repo's own convention (see directory_session.go's own
// doc comment) is to keep each ForceCommand parser self-contained rather
// than introduce a cross-cutting dependency between them.
var portalFQDNLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
var portalIPv4LikeRe = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)

// parsePortalConnectFQDN strictly validates the <target-fqdn> half of the
// `pilot-connect <session-id> <target-fqdn>` grammar (spec.md §17.1): ASCII
// DNS hostname only, lowercase, at least two labels, no "@"/":"/"/"/
// whitespace, no leading "-", no trailing ".", no shell metacharacter,
// never an IP literal. Any violation is rejected outright.
func parsePortalConnectFQDN(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.ContainsAny(s, " \t\r\n@:/\\;|&$`<>(){}[]'\"*?!#~^") {
		return "", fmt.Errorf("invalid character in target %q", s)
	}
	if strings.HasPrefix(s, "-") {
		return "", fmt.Errorf("target %q must not start with -", s)
	}
	if strings.HasSuffix(s, ".") {
		return "", fmt.Errorf("target %q must not end with a trailing dot", s)
	}
	if portalIPv4LikeRe.MatchString(s) {
		return "", fmt.Errorf("target %q is an IP literal, not an FQDN", s)
	}
	if s != strings.ToLower(s) {
		return "", fmt.Errorf("target %q must be lowercase", s)
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("target %q is not FQDN-shaped", s)
	}
	for _, label := range labels {
		if !portalFQDNLabelRe.MatchString(label) {
			return "", fmt.Errorf("target %q has an invalid label %q", s, label)
		}
	}
	return s, nil
}

// Exact captive-transport grammar prefixes (docs/superpowers/specs/
// 2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md §7.1):
// the prefix including its single trailing space, then exactly one FQDN
// token validated by parsePortalConnectFQDN — the same rules as
// pilot-connect's target, so the two grammars can never drift apart.
const (
	portalTransportCommandPrefix  = "pilot-transport-v1 "
	portalKnownHostsCommandPrefix = "pilot-known-hosts-v1 "
)

// portalSessionKind is which of the four states a SSH_ORIGINAL_COMMAND
// dispatches to (captive-transport spec §7.1).
type portalSessionKind int

const (
	portalSessionUnknown portalSessionKind = iota
	portalSessionInteractive
	portalSessionConnect
	portalSessionTransport
	portalSessionKnownHosts
)

// portalSessionCommand is one strictly-parsed SSH_ORIGINAL_COMMAND.
// SessionID is set only for portalSessionConnect.
type portalSessionCommand struct {
	Kind      portalSessionKind
	SessionID string
	Target    string
}

// parsePortalSSHOriginalCommand implements the exact dispatch: empty ->
// interactive TUI, "pilot-connect <uuid> <fqdn>" -> one-shot connect,
// "pilot-transport-v1 <fqdn>" -> opaque transport, "pilot-known-hosts-v1
// <fqdn>" -> known_hosts lines, anything else -> deny. It never falls back
// to any shell-tokenization behavior — the only string operations are
// fixed-prefix checks, a single split on the one interior space
// pilot-connect allows, a UUID syntax check, and the strict FQDN parse
// above.
//
// On a transport/known-hosts grammar error the returned Kind is still that
// state (the prefix matched), so the caller can report the state's own
// usage message; an unrecognized command returns portalSessionUnknown.
//
// session-id is validated for SYNTAX ONLY (spec.md §17.2: "不把 session ID
// 當 proof") — it is never compared against anything Directory claims, and
// authorization never reads it. It exists purely for log correlation.
func parsePortalSSHOriginalCommand(raw string) (portalSessionCommand, error) {
	switch {
	case raw == "":
		return portalSessionCommand{Kind: portalSessionInteractive}, nil
	case strings.HasPrefix(raw, portalConnectCommandPrefix):
		rest := raw[len(portalConnectCommandPrefix):]
		sessionID, target, ok := strings.Cut(rest, " ")
		if !ok {
			return portalSessionCommand{}, fmt.Errorf("unrecognized command")
		}
		// Exactly two tokens after the fixed prefix — a second interior
		// space means a third argument was smuggled in, which this grammar
		// has no slot for and must reject, not silently ignore.
		if strings.Contains(target, " ") {
			return portalSessionCommand{}, fmt.Errorf("unrecognized command")
		}
		if _, err := uuid.Parse(sessionID); err != nil {
			return portalSessionCommand{}, fmt.Errorf("invalid session id: %w", err)
		}
		fqdn, err := parsePortalConnectFQDN(target)
		if err != nil {
			return portalSessionCommand{}, err
		}
		return portalSessionCommand{Kind: portalSessionConnect, SessionID: sessionID, Target: fqdn}, nil
	case strings.HasPrefix(raw, portalTransportCommandPrefix):
		fqdn, err := parsePortalConnectFQDN(raw[len(portalTransportCommandPrefix):])
		if err != nil {
			return portalSessionCommand{Kind: portalSessionTransport}, fmt.Errorf("%s: %w", transportMsgUsage, err)
		}
		return portalSessionCommand{Kind: portalSessionTransport, Target: fqdn}, nil
	case strings.HasPrefix(raw, portalKnownHostsCommandPrefix):
		fqdn, err := parsePortalConnectFQDN(raw[len(portalKnownHostsCommandPrefix):])
		if err != nil {
			return portalSessionCommand{Kind: portalSessionKnownHosts}, fmt.Errorf("%s: %w", knownHostsMsgUsage, err)
		}
		return portalSessionCommand{Kind: portalSessionKnownHosts, Target: fqdn}, nil
	default:
		return portalSessionCommand{}, fmt.Errorf("unrecognized command")
	}
}

// TTY probes, overridable in tests (captive-transport spec §7.3). The
// interactive Portal and pilot-connect require a TTY on stdin — the Go-side
// replacement for the wrapper's old `[ -t 0 ] || exit 1`, which could not
// stay once a no-TTY transport state exists. The opaque transport and
// known-hosts states forbid any TTY: a PTY would corrupt the binary stream.
var (
	portalSessionStdinIsTTY  = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	portalSessionStdoutIsTTY = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	portalSessionGetenv      = os.Getenv
)

func portalSessionHasAnyTTY() bool {
	return portalSessionStdinIsTTY() || portalSessionStdoutIsTTY() || portalSessionGetenv("SSH_TTY") != ""
}

// portalSessionCmd is the hidden entry point
// `/usr/local/libexec/pilot-session`'s wrapper script execs into. Hidden
// because it is never meant to be run interactively by an operator — it
// exists purely as sshd's ForceCommand target. SilenceUsage and
// SilenceErrors keep a denial to a single stderr line (cmd/pilot/main.go
// prints the error itself; cobra would print it a second time): for the
// transport states that stderr is shown straight in the user's terminal by
// their ProxyCommand/KnownHostsCommand.
var portalSessionCmd = &cobra.Command{
	Use:    "portal-session",
	Hidden: true,
	// The user's whole SSH session: a runtime failure must not print usage,
	// and runPortalSession prints each error exactly once itself.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPortalSession(cmd, os.Getenv("SSH_ORIGINAL_COMMAND"))
	},
}

func init() {
	rootCmd.AddCommand(portalSessionCmd)
}

// runPortalSession is portalSessionCmd's testable body.
func runPortalSession(cmd *cobra.Command, sshOriginalCommand string) error {
	parsed, err := parsePortalSSHOriginalCommand(sshOriginalCommand)
	if err != nil {
		if parsed.Kind == portalSessionTransport || parsed.Kind == portalSessionKnownHosts {
			return err // already carries that state's own usage prefix
		}
		return fmt.Errorf("pilot-session: %w", err)
	}
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}
	switch parsed.Kind {
	case portalSessionTransport:
		if portalSessionHasAnyTTY() {
			return errors.New(transportMsgTTYNotAllowed)
		}
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
		defer stop()
		emitter, _ := sessionaudit.NewEmitter("pilot-access-gateway")
		return runPortalTransport(ctx, portalTransportDeps{
			client:     newPortalClient(portalSocketFlag),
			resolver:   net.DefaultResolver,
			dialer:     &net.Dialer{},
			localAddrs: net.InterfaceAddrs,
			stdin:      os.Stdin,
			stdout:     os.Stdout,
			emitter:    emitter,
		}, parsed.Target)
	case portalSessionKnownHosts:
		if portalSessionHasAnyTTY() {
			return errors.New(knownHostsMsgTTYNotAllowed)
		}
		emitter, _ := sessionaudit.NewEmitter("pilot-access-gateway")
		return runPortalKnownHosts(ctx, newPortalClient(portalSocketFlag), emitter, os.Stdout, parsed.Target)
	}

	if !portalSessionStdinIsTTY() {
		return fmt.Errorf("pilot-session: a TTY is required for this session")
	}
	client := newPortalClient(portalSocketFlag)
	if parsed.Kind == portalSessionInteractive {
		return runPortalWithSSHConfig(ctx, client, portalSSHConfigFlag)
	}
	credentials := newPortalKerberosSession()
	defer credentials.Close()
	// The emitter tag matches this binary's own component name — a
	// central log consumer distinguishes Directory's vs. Gateway's events
	// by this syslog program tag (docs/tmp/now/spec.md §22). NewEmitter
	// never fails this command's real job (audit is best-effort — see
	// sessionaudit.Emitter's doc comment): an unreachable local syslog
	// degrades to logging via slog.Default() instead.
	emitter, _ := sessionaudit.NewEmitter("pilot-access-gateway")
	return runPortalOneShotConnect(ctx, client, credentials, emitter, portalSSHConfigFlag, parsed.SessionID, parsed.Target)
}
