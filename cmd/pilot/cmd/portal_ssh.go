// portal_ssh.go is Phase 5's controlled SSH launch (spec.md §16/§31/§32):
// a fresh /v1/connect/authorize check immediately before every connect,
// then a fixed-argv OpenSSH invocation using a root-owned config that
// ignores the caller's own ~/.ssh/config entirely.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// defaultSSHConfigPath / sshBinaryPath match spec.md §25/§31.
const (
	defaultSSHConfigPath = "/etc/pilot/ssh_config"
	sshBinaryPath        = "/usr/bin/ssh"
)

// pilotSSHConfig is the exact root-owned SSH client config spec.md §32
// mandates, verbatim. It is the single source of truth for both Phase
// 7's apply playbook (which installs it at /etc/pilot/ssh_config) and
// this phase's own verification test (portal_ssh_test.go actually runs
// `ssh -G` against it — spec.md §32: "每個 option要在 supported OpenSSH
// 執行 ssh -G -F /etc/pilot/ssh_config target 驗證").
//
// ProxyCommand relays the connection through SSSD's own resolver
// (sss_ssh_knownhostsproxy — the same tool freeipa-client-apply.yml's own
// ssh_config.d/04-ipa.conf already uses) instead of a GlobalKnownHostsFile
// snapshot taken once at apply time: a host added to pilot-target-<scope>
// afterward would otherwise have no entry and fail StrictHostKeyChecking
// until the next re-apply, and the old ssh-keyscan-based snapshot trusted
// whatever key a host presented with no verification at all (blind TOFU),
// weaker than resolving the host's actual enrollment-time ipaSshPubKey.
// GlobalKnownHostsFile still has to point at SSSD's own dynamically
// maintained cache (/var/lib/sss/pubconf/known_hosts, kept current by
// sssd itself as it resolves each host's ipaSshPubKey) — ProxyCommand
// only relays bytes, it does not by itself satisfy StrictHostKeyChecking
// (found live on vm-target: dropping GlobalKnownHostsFile entirely, on
// the theory that ProxyCommand alone was enough, produced "No ED25519
// host key is known ... Host key verification failed").
const pilotSSHConfig = `Host *
    ForwardAgent no
    ClearAllForwardings yes

    PermitLocalCommand no
    EnableEscapeCommandline no
    EscapeChar none

    ProxyJump none
    ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h

    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts

    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
    PreferredAuthentications gssapi-with-mic

    BatchMode yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication no
    PasswordAuthentication no

    RequestTTY force
`

// buildConnectSSHCmd builds the fixed-argv OpenSSH invocation spec.md §31
// requires: no free-text hostname, no user@host, no IP, no port, no SSH
// options, no remote command. target is the only variable part, and its
// only caller (connectToHost, below) only ever passes the Target field
// of a fresh ConnectAuthorize response — never anything the user typed
// directly into a prompt.
func buildConnectSSHCmd(sshConfigPath, target, credentialCache string) *exec.Cmd {
	cmd := exec.Command(sshBinaryPath, "-F", sshConfigPath, target)
	if credentialCache != "" {
		cmd.Env = replaceProcessEnv(os.Environ(), "KRB5CCNAME", credentialCache)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// sshLauncher runs the built ssh command. Overridden by tests so they can
// observe/assert on the command that would have been run without
// exec'ing a real ssh session to a real host.
var sshLauncher = func(cmd *exec.Cmd) error { return cmd.Run() }

// connectToHost is Phase 5's Connect action. It performs a fresh,
// full re-authorize immediately before connecting (spec.md §16: "Connect
// 每次 fresh authorize" — never reusing My Hosts' cached SSH.Allowed as
// the connect decision), then launches the controlled OpenSSH client.
//
// It always returns nil, back into runPortal's own loop (spec.md §2:
// "退出 remote SSH 後回到同一個 pilot portal") — a failed authorize call or
// a nonzero ssh exit (host unreachable, connection refused, wrong host
// key, the user just detaching, ...) are all completely ordinary outcomes
// here, not fatal errors: propagating them used to unwind all the way out
// of runPortal and kill the whole interactive session with a raw exec
// error and cobra's usage dump — the opposite of "return to portal"
// (found live: selecting one of the placeholder fixture hosts in a demo
// environment, which has no real machine behind it, crashed the entire
// TUI instead of just failing that one Connect attempt).
//
// Note this package's Portal is NOT one continuous Bubble Tea Program
// (unlike spec.md §60 Phase 5's "tea.ExecProcess" wording assumes) — it
// is a sequence of short-lived one-shot Programs, the same pattern
// deploy_tui.go already uses (see its own package doc comment for why).
// Between any two prompts there is no active raw-mode Program to suspend,
// so a plain blocking exec.Cmd.Run() here already leaves the terminal in
// the right state for the next prompt's Program to start — no
// suspend/resume machinery is needed, and adding tea.ExecProcess would
// only reintroduce complexity this architecture doesn't have a use for.
func connectToHost(ctx context.Context, client *portalClient, credentials portalCredentialSession, sshConfigPath, username, fqdn string) error {
	authz, err := client.ConnectAuthorize(ctx, fqdn)
	if err != nil {
		runConfirmPrompt("", fmt.Sprintf("Connect failed.\n\n%v", err), true)
		return nil
	}
	if !authz.Allowed {
		runConfirmPrompt("", "Access changed.\nConnection was not started.", true)
		return nil
	}
	cache, err := credentials.Ensure(ctx, username)
	if err != nil {
		runConfirmPrompt("", fmt.Sprintf("Kerberos authentication failed.\n\n%v", err), true)
		return nil
	}
	if err := sshLauncher(buildConnectSSHCmd(sshConfigPath, authz.Target, cache)); err != nil {
		runConfirmPrompt("", fmt.Sprintf("SSH session ended with an error.\n\n%v", err), true)
	}
	return nil
}
