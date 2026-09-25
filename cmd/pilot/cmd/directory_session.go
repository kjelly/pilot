// directory_session.go is the Go-side handler for sshd's
// `ForceCommand /usr/local/libexec/pilot-directory-session` (docs/tmp/
// now/spec.md §14/D7). The libexec entry point itself is a tiny shell
// script that unsets a handful of inherited env vars and execs `pilot
// directory-session` (mirroring pilot-access-gateway's own
// /usr/local/libexec/pilot-session wrapper shape exactly) — critically,
// that shell script NEVER references $SSH_ORIGINAL_COMMAND itself. This
// command reads it directly via os.Getenv, in Go, and strictly parses it
// here — spec.md D7's absolute prohibition ("SSH_ORIGINAL_COMMAND 永遠不
// 得交給 shell") is about never handing that string to `sh -c`/`bash -c`/
// `eval`; reading an inherited environment variable in a Go process is
// not shell interpretation, and no shell is ever invoked with it as
// input anywhere in this file.
package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// directoryConnectCommandPrefix is the exact, fixed grammar spec.md §14
// requires: SSH_ORIGINAL_COMMAND is either empty (-> pilot directory) or
// exactly "pilot-directory-connect <fqdn>" (-> one-shot connect) — never
// interpreted as a shell command line.
const directoryConnectCommandPrefix = "pilot-directory-connect "

// directoryFQDNLabelRe matches one DNS label: lowercase alphanumeric,
// optionally hyphenated internally, never leading/trailing "-" — the
// same shape a real FQDN label takes, hand-rolled here rather than
// imported from internal/inventory (accessdirectory-adjacent code
// deliberately has no roster/inventory dependency, spec.md §8.1's same
// discipline extended to this ForceCommand parser).
var directoryFQDNLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// directoryIPv4LikeRe rejects a dotted-decimal IPv4 literal presented
// where an FQDN is required (spec.md §17.1: "IP literal一律拒絕").
var directoryIPv4LikeRe = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)

// parseDirectoryConnectFQDN strictly validates the <fqdn> half of the
// `pilot-directory-connect <fqdn>` grammar (spec.md §17.1's rules,
// applied to Directory's own handoff command in the same spirit as the
// Gateway-side pilot-connect grammar): ASCII DNS hostname only, lowercase,
// at least two labels, no "@"/":"/"/"/whitespace, no leading "-", no
// trailing ".", no shell metacharacter, never an IP literal. Any
// violation is rejected outright — there is no partial-acceptance or
// best-effort canonicalization here, since this string is about to
// select which Gateway candidate list to use, not just a display value.
func parseDirectoryConnectFQDN(s string) (string, error) {
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
	if directoryIPv4LikeRe.MatchString(s) {
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
		if !directoryFQDNLabelRe.MatchString(label) {
			return "", fmt.Errorf("target %q has an invalid label %q", s, label)
		}
	}
	return s, nil
}

// parseDirectorySSHOriginalCommand implements spec.md §14's exact
// dispatch: empty -> interactive TUI, exact grammar match -> one-shot
// connect, anything else -> deny. It never falls back to any
// shell-tokenization behavior — the only string operation performed is a
// single fixed-prefix check plus the strict FQDN parse above.
func parseDirectorySSHOriginalCommand(raw string) (fqdn string, interactive bool, err error) {
	if raw == "" {
		return "", true, nil
	}
	if !strings.HasPrefix(raw, directoryConnectCommandPrefix) {
		return "", false, fmt.Errorf("unrecognized command")
	}
	rest := raw[len(directoryConnectCommandPrefix):]
	// Exactly one token after the fixed prefix — a second space means a
	// second argument was smuggled in, which this grammar has no slot
	// for and must reject, not silently ignore.
	if strings.Contains(rest, " ") {
		return "", false, fmt.Errorf("unrecognized command")
	}
	target, err := parseDirectoryConnectFQDN(rest)
	if err != nil {
		return "", false, err
	}
	return target, false, nil
}

// directorySessionCmd is the hidden entry point
// `/usr/local/libexec/pilot-directory-session`'s wrapper script execs
// into. Hidden because it is never meant to be run interactively by an
// operator — it exists purely as sshd's ForceCommand target.
var directorySessionCmd = &cobra.Command{
	Use:    "directory-session",
	Hidden: true,
	// The user's whole SSH session: a runtime failure must not print usage.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDirectorySession(cmd, os.Getenv("SSH_ORIGINAL_COMMAND"))
	},
}

func init() {
	rootCmd.AddCommand(directorySessionCmd)
}

// runDirectorySession is directorySessionCmd's testable body.
func runDirectorySession(cmd *cobra.Command, sshOriginalCommand string) error {
	target, interactive, err := parseDirectorySSHOriginalCommand(sshOriginalCommand)
	if err != nil {
		return fmt.Errorf("pilot-directory-session: %w", err)
	}
	if interactive {
		client := newDirectoryClient(directorySocketFlag)
		return runDirectoryWithSSHConfig(cmd.Context(), client, directorySSHConfigFlag)
	}
	// One-shot `pilot-directory-connect <fqdn>` (spec.md §14): the actual
	// Gateway-side one-shot connect protocol (spec.md §16-§18) is Phase 5
	// work — Phase 4 only needs the strict parse above to already reject
	// every malformed/malicious SSH_ORIGINAL_COMMAND before ever reaching
	// this branch. Returning a clear, non-zero-exit "not implemented yet"
	// here (rather than silently succeeding, or worse, guessing at a
	// connect flow this phase hasn't built the server-side half of) keeps
	// the failure mode honest.
	return fmt.Errorf("pilot-directory-session: one-shot connect to %q not yet implemented (spec.md Phase 5)", target)
}
