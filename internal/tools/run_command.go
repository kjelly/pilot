package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/sandbox"
)

// shellMetachars lists characters that, if present in a "command"
// string, indicate an attempt to chain a second command or otherwise
// break out of the intended argv-based invocation. We reject any
// command containing any of these bytes.
//
// Note: the previous implementation used "bash -c <cmd>" which is
// inherently shell-interpreted. We now parse the command into argv
// ourselves and call exec.Command(bin, args...) directly — no shell.
var shellMetachars = []string{
	";", "&&", "||", "|", "`", "$(",
	">", ">>", "<", "<<",
	"&", "\n", "\r",
}

// ArgPattern matches a single positional argument of a whitelisted
// command. Either Exact or Prefix is set (mutually exclusive).
type ArgPattern struct {
	Exact  string
	Prefix string
}

func (a ArgPattern) Match(s string) bool {
	if a.Exact != "" {
		return s == a.Exact
	}
	if a.Prefix != "" {
		return strings.HasPrefix(s, a.Prefix)
	}
	return false
}

type CmdSpec struct {
	Program string
	Args    []ArgPattern // optional positional constraints
}

// isWhitelisted returns true when argv matches an entry in the whitelist.
// The first element is the program name; the rest are checked positionally.
func isWhitelisted(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, spec := range commandWhitelist {
		if spec.Program != argv[0] {
			continue
		}
		if len(argv)-1 < len(spec.Args) {
			continue
		}
		ok := true
		for i, pat := range spec.Args {
			if !pat.Match(argv[i+1]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// SplitCommand parses a command line into argv tokens. It does NOT
// interpret any shell metacharacter — instead it rejects the input
// outright if any is present. Quoting is supported so values like
// `cat "/etc/os-release"` and `systemctl status "sshd.service"`
// round-trip faithfully.
func SplitCommand(s string) ([]string, error) {
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return nil, fmt.Errorf("shell metacharacter %q is not allowed", mc)
		}
	}
	var argv []string
	var cur strings.Builder
	var quote rune // 0 = no quote, '"' or '\''
	for _, r := range s {
		switch {
		case r == '"' || r == '\'':
			switch quote {
			case 0:
				quote = r
			case r:
				quote = 0
			default:
				cur.WriteRune(r)
			}
		case (r == ' ' || r == '\t') && quote == 0:
			if cur.Len() > 0 {
				argv = append(argv, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if cur.Len() > 0 {
		argv = append(argv, cur.String())
	}
	return argv, nil
}

// commandWhitelist is the canonical allow-list. Every approved command
// must appear here with positional argument constraints.
var commandWhitelist = []CmdSpec{
	// Inspection / read-only
	{Program: "uname", Args: []ArgPattern{{Exact: "-a"}}},

	{Program: "cat"}, // paths checked in Execute() against AllowedReadPaths

	{Program: "systemctl", Args: []ArgPattern{{Exact: "status"}}},
	{Program: "systemctl", Args: []ArgPattern{{Exact: "is-active"}}},
	{Program: "systemctl", Args: []ArgPattern{{Exact: "is-enabled"}}},

	{Program: "ss", Args: []ArgPattern{{Exact: "-tlnp"}}},
	{Program: "ss", Args: []ArgPattern{{Exact: "-ulnp"}}},

	{Program: "ps", Args: []ArgPattern{{Exact: "aux"}}},

	{Program: "ip", Args: []ArgPattern{{Exact: "addr"}, {Exact: "show"}}},
	{Program: "ip", Args: []ArgPattern{{Exact: "route"}, {Exact: "show"}}},

	// sysctl read-only: a single key-like arg. No `-w`/`--write` flag.
	{Program: "sysctl", Args: []ArgPattern{{Prefix: "net."}}},
	{Program: "sysctl", Args: []ArgPattern{{Prefix: "kernel."}}},
	{Program: "sysctl", Args: []ArgPattern{{Prefix: "vm."}}},
	{Program: "sysctl", Args: []ArgPattern{{Prefix: "fs."}}},

	{Program: "aa-status"},
	{Program: "ufw", Args: []ArgPattern{{Exact: "status"}}},
	{Program: "ufw", Args: []ArgPattern{{Exact: "status"}}},

	{Program: "id"},
	{Program: "whoami"},
	{Program: "date"},
	{Program: "uptime"},
	{Program: "dpkg", Args: []ArgPattern{{Exact: "-l"}}},
	{Program: "apt", Args: []ArgPattern{{Exact: "list"}, {Exact: "--upgradable"}}},
}

type RunCommandTool struct {
	// AllowedReadPaths restricts `cat` invocations to these prefixes
	// (in addition to the global read_file restrictions). If empty,
	// `cat` is not permitted at all.
	AllowedReadPaths []string
	// AllowedCommands is a list of dynamic commands whitelisted from the config.
	AllowedCommands []CmdSpec
	// Env, when non-nil, redirects exec through the sandbox
	// environment. If nil, exec runs on the local host. Set by
	// app.New from cfg.Sandbox.
	Env sandbox.Environment
}

func (t *RunCommandTool) Spec() *Spec {
	return &Spec{
		Name:          "run_command",
		Description:   "Execute a read-only shell command on the local host. The command must be on the approved whitelist (systemctl status, ss, ip, sysctl, aa-status, ufw, dpkg, etc.). Mutating commands, shell metacharacters (; | & $ ` > <), and arbitrary reads are rejected.",
		RiskLevel:     "medium",
		Reversible:    true,
		DoubleConfirm: true,
		DryRunSafe:    true, // only read-only whitelist commands are allowed
		Parameters:    runCommandArgs,
	}
}

// ValidateCatArg enforces that `cat` only reads from safe paths.
func (t *RunCommandTool) ValidateCatArg(path string) error {
	if strings.ContainsAny(path, "*{}[]?") {
		return fmt.Errorf("globs not allowed in cat path")
	}
	if len(t.AllowedReadPaths) == 0 {
		return fmt.Errorf("cat target %q is not in the allowed read paths", path)
	}
	for _, prefix := range t.AllowedReadPaths {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}
	return fmt.Errorf("cat target %q is not in the allowed read paths", path)
}

func (t *RunCommandTool) isWhitelisted(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	// Check tool-specific allowed commands
	for _, spec := range t.AllowedCommands {
		if spec.Program != argv[0] {
			continue
		}
		if len(argv)-1 < len(spec.Args) {
			continue
		}
		ok := true
		for i, pat := range spec.Args {
			if !pat.Match(argv[i+1]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	// Fallback to global default whitelist
	return isWhitelisted(argv)
}

func (t *RunCommandTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Command    string `json:"command"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("run_command: invalid args: %w", err)
	}
	if a.Command == "" {
		return nil, fmt.Errorf("run_command: command is required")
	}
	cmdStr := strings.TrimSpace(a.Command)

	argv, err := SplitCommand(cmdStr)
	if err != nil {
		return &Result{
			Content: fmt.Sprintf("ERROR: %v. Use a flat argv-style command without pipes, semicolons, redirections, or subshells.", err),
			IsError: true,
		}, nil
	}
	if !t.isWhitelisted(argv) {
		return &Result{
			Content: fmt.Sprintf("ERROR: command %q is not on the whitelist. Allowed: read-only inspection commands (systemctl status, ss, ip, sysctl <read-only>, aa-status, ufw, dpkg).", cmdStr),
			IsError: true,
		}, nil
	}

	// Extra constraints for `cat`: each positional arg must be an allowed path.
	if argv[0] == "cat" {
		for _, p := range argv[1:] {
			if err := t.ValidateCatArg(p); err != nil {
				return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
			}
		}
	}

	// Extra constraints for `sysctl`: reject any flag (defense in depth —
	// the whitelist already requires a key-shaped arg as argv[1]).
	if argv[0] == "sysctl" {
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") {
				return &Result{
					Content: fmt.Sprintf("ERROR: sysctl flags are not permitted (read-only tool); got flag %q", a),
					IsError: true,
				}, nil
			}
		}
	}

	timeout := 30 * time.Second
	if a.TimeoutSec > 0 {
		timeout = time.Duration(a.TimeoutSec) * time.Second
	}

	// Sandbox-aware exec. When Env is set, route the call through
	// the sandbox Environment (e.g. docker exec inside a managed
	// container). The whitelist still applies because we validate
	// argv BEFORE the routing — sandbox is a transport detail, not
	// a policy change.
	if t.Env != nil {
		res, err := t.Env.Exec(ctx, argv, sandbox.ExecOptions{Timeout: timeout})
		if err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
		}
		out := res.Stdout
		if res.Stderr != "" {
			out += "\n--- stderr ---\n" + res.Stderr
		}
		if res.ExitCode != 0 {
			return &Result{
				Content: fmt.Sprintf("ERROR (exit %d): %s", res.ExitCode, out),
				IsError: true,
			}, nil
		}
		return &Result{Content: out}, nil
	}

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Direct exec — NO shell. The argv has already been whitelisted.
	cmd := exec.CommandContext(c, argv[0], argv[1:]...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
	}
	var sb strings.Builder
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
		if sb.Len() > 50*1024 {
			sb.WriteString("... [truncated]\n")
			break
		}
	}
	escan := bufio.NewScanner(stderr)
	escan.Buffer(make([]byte, 16*1024), 256*1024)
	var esb strings.Builder
	for escan.Scan() {
		esb.WriteString(escan.Text())
		esb.WriteString("\n")
	}
	err = cmd.Wait()
	out := sb.String()
	if esb.Len() > 0 {
		out += "\n--- stderr ---\n" + esb.String()
	}
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR (exit non-zero): %s\n%s", err, out), IsError: true}, nil
	}
	return &Result{Content: out}, nil
}
