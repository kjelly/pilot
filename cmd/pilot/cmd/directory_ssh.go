// directory_ssh.go is the Directory -> Gateway SSH hop (docs/tmp/now/
// spec.md §15/§16/§19): a fresh /v1/connect/resolve immediately before
// every connect, then a fixed-argv OpenSSH invocation carrying the
// spec.md §16 handoff grammar (`pilot-connect <session-id> <target-fqdn>`)
// as the remote command — never a free-text hostname, never a
// caller-supplied SSH option.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// defaultDirectorySSHConfigPath matches spec.md §15's
// /etc/pilot/directory_ssh_config — the Directory-owned, root-installed
// SSH client config for the Directory -> Gateway hop, rendered by
// playbooks/apply/pilot-access-directory-apply.yml. This package never
// renders it; it only ever passes the path to `-F`.
const defaultDirectorySSHConfigPath = "/etc/pilot/directory_ssh_config"

// buildDirectoryConnectSSHCmd builds the fixed-argv OpenSSH invocation
// spec.md §16 requires: no user@host, no IP, no port, no other SSH
// option, and the remote command is always exactly
// `pilot-connect <sessionID> <targetFQDN>` — both values only ever come
// from a fresh POST /v1/connect/resolve response (see connectToGateway,
// below), never anything a user typed into a prompt.
func buildDirectoryConnectSSHCmd(sshConfigPath, gatewayFQDN, sessionID, targetFQDN, credentialCache string) *exec.Cmd {
	cmd := exec.Command(sshBinaryPath, "-F", sshConfigPath, gatewayFQDN, "--", "pilot-connect", sessionID, targetFQDN)
	if credentialCache != "" {
		cmd.Env = replaceProcessEnv(os.Environ(), "KRB5CCNAME", credentialCache)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// directorySSHLauncher runs the built ssh command. Overridden by tests so
// they can observe/assert on the command that would have been run
// without exec'ing a real ssh session to a real host — same pattern as
// portal_ssh.go's sshLauncher, kept as a separate variable so Directory
// and Portal tests never interfere with each other's stubbing.
var directorySSHLauncher = func(cmd *exec.Cmd) error { return cmd.Run() }

// connectToGateway is Directory's Connect action. It performs a fresh,
// full re-resolve immediately before connecting (spec.md D1/D10: "Connect
// 每次呼叫 /v1/connect/resolve 後才啟動 SSH" — never reusing My Hosts'
// cached route as the connect decision), then tries each candidate
// Gateway FQDN in the resolved route in order (spec.md §19: deterministic
// failover on a transport-level failure to reach one candidate — trying
// the next). It does NOT attempt to distinguish an explicit Gateway-side
// authorization deny from an ordinary "session ran and exited" outcome by
// ssh exit code alone; spec.md §19 point 8's rule (never retry PAST an
// explicit deny) is a Phase 5 concern once the Gateway's own
// pilot-connect parser exists server-side and can report that
// distinction back — Phase 4 has no such protocol yet, so this only
// implements straightforward sequential failover on an outright ssh
// command failure.
//
// Like portal_ssh.go's connectToHost, this always returns nil back into
// the Directory TUI loop (spec.md AD22: "target exit 后回 Directory") — a
// failed resolve, credential failure, or nonzero ssh exit are all
// ordinary outcomes here, never fatal errors that would unwind out of
// runDirectory and kill the whole interactive session.
func connectToGateway(ctx context.Context, client *directoryClient, credentials portalCredentialSession, sshConfigPath, username, targetFQDN string) error {
	resolved, err := client.ConnectResolve(ctx, targetFQDN)
	if err != nil {
		runConfirmPrompt("", fmt.Sprintf("Connect failed.\n\n%v", err), true)
		return nil
	}
	if !resolved.Allowed || resolved.Route == nil || len(resolved.Route.GatewayCandidates) == 0 {
		runConfirmPrompt("", "Access changed.\nConnection was not started.", true)
		return nil
	}
	cache, err := credentials.Ensure(ctx, username)
	if err != nil {
		runConfirmPrompt("", fmt.Sprintf("Kerberos authentication failed.\n\n%v", err), true)
		return nil
	}
	var lastErr error
	for _, gatewayFQDN := range resolved.Route.GatewayCandidates {
		cmd := buildDirectoryConnectSSHCmd(sshConfigPath, gatewayFQDN, resolved.SessionID, resolved.Target, cache)
		if err := directorySSHLauncher(cmd); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		runConfirmPrompt("", fmt.Sprintf("SSH session ended with an error.\n\n%v", lastErr), true)
	}
	return nil
}
