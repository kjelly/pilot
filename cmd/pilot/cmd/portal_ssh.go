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
const pilotSSHConfig = `Host *
    ForwardAgent no
    ClearAllForwardings yes

    PermitLocalCommand no
    EnableEscapeCommandline no
    EscapeChar none

    ProxyJump none
    ProxyCommand none

    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /etc/pilot/ssh_known_hosts

    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes

    KbdInteractiveAuthentication yes
    PasswordAuthentication yes

    RequestTTY force
`

// buildConnectSSHCmd builds the fixed-argv OpenSSH invocation spec.md §31
// requires: no free-text hostname, no user@host, no IP, no port, no SSH
// options, no remote command. target is the only variable part, and its
// only caller (connectToHost, below) only ever passes the Target field
// of a fresh ConnectAuthorize response — never anything the user typed
// directly into a prompt.
func buildConnectSSHCmd(sshConfigPath, target string) *exec.Cmd {
	cmd := exec.Command(sshBinaryPath, "-F", sshConfigPath, target)
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
func connectToHost(ctx context.Context, client *portalClient, sshConfigPath, fqdn string) error {
	authz, err := client.ConnectAuthorize(ctx, fqdn)
	if err != nil {
		runConfirmPrompt("", fmt.Sprintf("Connect failed.\n\n%v", err), true)
		return nil
	}
	if !authz.Allowed {
		runConfirmPrompt("", "Access changed.\nConnection was not started.", true)
		return nil
	}
	if err := sshLauncher(buildConnectSSHCmd(sshConfigPath, authz.Target)); err != nil {
		runConfirmPrompt("", fmt.Sprintf("SSH session ended with an error.\n\n%v", err), true)
	}
	return nil
}
