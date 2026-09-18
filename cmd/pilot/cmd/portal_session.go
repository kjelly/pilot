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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
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

// portalConnectCommand is one strictly-parsed `pilot-connect <session-id>
// <target-fqdn>` invocation.
type portalConnectCommand struct {
	SessionID string
	Target    string
}

// parsePortalSSHOriginalCommand implements spec.md §17's exact dispatch:
// empty -> interactive TUI, exact grammar match -> one-shot connect,
// anything else -> deny. It never falls back to any shell-tokenization
// behavior — the only string operations performed are a fixed-prefix
// check, a single split on the one interior space the grammar allows, a
// UUID syntax check, and the strict FQDN parse above.
//
// session-id is validated for SYNTAX ONLY (spec.md §17.2: "不把 session ID
// 當 proof") — it is never compared against anything Directory claims, and
// authorization below never reads it. It exists purely for future
// (Phase 6) log correlation.
func parsePortalSSHOriginalCommand(raw string) (cmd *portalConnectCommand, interactive bool, err error) {
	if raw == "" {
		return nil, true, nil
	}
	if !strings.HasPrefix(raw, portalConnectCommandPrefix) {
		return nil, false, fmt.Errorf("unrecognized command")
	}
	rest := raw[len(portalConnectCommandPrefix):]
	sessionID, target, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, false, fmt.Errorf("unrecognized command")
	}
	// Exactly two tokens after the fixed prefix — a second interior space
	// means a third argument was smuggled in, which this grammar has no
	// slot for and must reject, not silently ignore.
	if strings.Contains(target, " ") {
		return nil, false, fmt.Errorf("unrecognized command")
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil, false, fmt.Errorf("invalid session id: %w", err)
	}
	fqdn, err := parsePortalConnectFQDN(target)
	if err != nil {
		return nil, false, err
	}
	return &portalConnectCommand{SessionID: sessionID, Target: fqdn}, false, nil
}

// portalSessionCmd is the hidden entry point
// `/usr/local/libexec/pilot-session`'s wrapper script execs into. Hidden
// because it is never meant to be run interactively by an operator — it
// exists purely as sshd's ForceCommand target.
var portalSessionCmd = &cobra.Command{
	Use:    "portal-session",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPortalSession(cmd, os.Getenv("SSH_ORIGINAL_COMMAND"))
	},
}

func init() {
	rootCmd.AddCommand(portalSessionCmd)
}

// runPortalSession is portalSessionCmd's testable body.
func runPortalSession(cmd *cobra.Command, sshOriginalCommand string) error {
	connect, interactive, err := parsePortalSSHOriginalCommand(sshOriginalCommand)
	if err != nil {
		return fmt.Errorf("pilot-session: %w", err)
	}
	client := newPortalClient(portalSocketFlag)
	if interactive {
		return runPortalWithSSHConfig(cmd.Context(), client, portalSSHConfigFlag)
	}
	credentials := newPortalKerberosSession()
	defer credentials.Close()
	return runPortalOneShotConnect(cmd.Context(), client, credentials, portalSSHConfigFlag, connect.SessionID, connect.Target)
}
