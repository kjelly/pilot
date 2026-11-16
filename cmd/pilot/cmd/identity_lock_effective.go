package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/childproc"
)

// What the identity lock must agree with (issue #319): the host and the ssh
// settings ansible-playbook is going to use. Ansible does not read them from
// the inventory alone. It layers, in this order (highest first): extra vars
// (-e key=value, JSON, @file), the inventory's host and group variables, and
// the connection settings of ansible.cfg and the ANSIBLE_* environment
// variables. Reading the inventory alone locks host A while a `-e @file` that
// sets ansible_host sends the playbook to host B.
//
// The lock does not re-implement that layering. It asks Ansible for each layer
// the way the playbook run will see it: ansible-inventory with the playbook's
// own -e / vault arguments for the first two (identityLockRequest.ExtraArgs),
// ansible-config for the last (loadAnsibleConnectionConfig). A setting that
// pilot's ssh cannot honor is refused with its source named, exactly as it is
// when the inventory sets it (sshdial.TargetFromHostVars).
//
// Which hosts the playbook runs on is a narrower question than which variables
// it sees: the `hosts:` of the identity playbooks is templated with the extra
// vars only, so target_group is read from that layer alone
// (loadEffectiveTargetGroup), not from the merged host variables.

// identityDefaultTargetGroup is the hosts: pattern of the identity playbooks
// when nothing sets target_group.
const identityDefaultTargetGroup = "freeipa-server"

// connectionDefaults are the connection settings ansible.cfg and the ANSIBLE_*
// environment give every host, in the names of the host variables that would
// override them.
type connectionDefaults struct {
	// Vars is keyed by the host variable TargetFromHostVars reads.
	Vars map[string]any
	// Origins say where each Vars entry came from ("env: ANSIBLE_SSH_ARGS", or
	// the ansible.cfg file), for the message of a refusal.
	Origins map[string]string
	// AskPass is where ask_pass was turned on, or "" when it was not: Ansible
	// then asks for an ssh password, which pilot's ssh (BatchMode) cannot.
	AskPass string
}

// sshPluginOptionVars maps the options of Ansible's ssh connection plugin that
// decide where and as whom a run connects to the host variable that overrides
// each. Options outside this table (host_key_checking, pipelining, timeout,
// the ControlPath directory, ...) change neither the machine nor the identity.
var sshPluginOptionVars = map[string]string{
	"port":             "ansible_port",
	"remote_user":      "ansible_user",
	"private_key_file": "ansible_ssh_private_key_file",
	"ssh_args":         "ansible_ssh_args",
	"ssh_common_args":  "ansible_ssh_common_args",
	"ssh_extra_args":   "ansible_ssh_extra_args",
	"ssh_executable":   "ansible_ssh_executable",
}

// ansibleConfigEntry is one setting in the output of `ansible-config dump
// --format json`.
type ansibleConfigEntry struct {
	Name   string `json:"name"`
	Origin string `json:"origin"`
	Value  any    `json:"value"`
}

// parseAnsibleConnectionConfig reads `ansible-config dump --only-changed -t all
// --format json`. A document that does not have the shape this reads is an
// error, never "no settings": a changed output format must not silently turn
// the check off.
func parseAnsibleConnectionConfig(raw []byte) (connectionDefaults, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return connectionDefaults{}, fmt.Errorf("parse ansible-config output: %w", err)
	}
	out := connectionDefaults{Vars: map[string]any{}, Origins: map[string]string{}}
	sawConfigFile, sawConnectionPlugins := false, false
	for _, item := range items {
		var entry ansibleConfigEntry
		if err := json.Unmarshal(item, &entry); err == nil && entry.Name != "" {
			switch entry.Name {
			case "CONFIG_FILE":
				sawConfigFile = true
			case "DEFAULT_TRANSPORT":
				out.set("ansible_connection", entry)
			case "DEFAULT_ASK_PASS":
				if on, _ := entry.Value.(bool); on {
					out.AskPass = describeConfigOrigin(entry.Origin)
				}
			}
			continue
		}
		var section map[string]json.RawMessage
		if err := json.Unmarshal(item, &section); err != nil {
			return connectionDefaults{}, fmt.Errorf("parse ansible-config output: %w", err)
		}
		rawPlugins, ok := section["CONNECTION_PLUGINS"]
		if !ok {
			continue
		}
		sawConnectionPlugins = true
		var plugins []map[string][]ansibleConfigEntry
		if err := json.Unmarshal(rawPlugins, &plugins); err != nil {
			return connectionDefaults{}, fmt.Errorf("parse the connection plugins of the ansible-config output: %w", err)
		}
		for _, plugin := range plugins {
			for _, entry := range plugin["ssh"] {
				if hostVar, ok := sshPluginOptionVars[entry.Name]; ok {
					out.set(hostVar, entry)
				}
			}
		}
	}
	if !sawConfigFile || !sawConnectionPlugins {
		return connectionDefaults{}, fmt.Errorf("parse ansible-config output: no CONFIG_FILE or CONNECTION_PLUGINS entry, so it is not the document this reads")
	}
	return out, nil
}

func (d *connectionDefaults) set(hostVar string, entry ansibleConfigEntry) {
	d.Vars[hostVar] = entry.Value
	d.Origins[hostVar] = describeConfigOrigin(entry.Origin)
}

// describeConfigOrigin names where a setting came from: ansible-config prints
// "env: NAME" for an environment variable and the file path for an ini file.
func describeConfigOrigin(origin string) string {
	switch {
	case origin == "":
		return "ansible-config"
	case strings.HasPrefix(origin, "env: "):
		return origin
	default:
		return "ansible.cfg (" + origin + ")"
	}
}

// loadAnsibleConnectionConfig asks ansible-config for the connection settings
// that differ from Ansible's defaults, in the environment (the runtime of ctx)
// and working directory the playbook run will have, so that the same ansible.cfg
// is found.
func loadAnsibleConnectionConfig(ctx context.Context) (connectionDefaults, error) {
	command := deployAnsibleCommand(ctx, "ansible-config", "dump", "--only-changed", "-t", "all", "--format", "json")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	release, err := ansible.HoldCommandLog(ctx, command)
	if err == nil {
		err = command.Run()
		release()
	}
	if err != nil {
		return connectionDefaults{}, fmt.Errorf("ansible-config dump: %w: %s", childproc.Cause(ctx, err), strings.TrimSpace(stderr.String()))
	}
	return parseAnsibleConnectionConfig([]byte(stdout.String()))
}

// withConnectionDefaults returns hostVars with the configured defaults filled in
// for the connection variables the host does not set itself (a host or extra
// variable always wins over ansible.cfg and the environment, as it does in
// Ansible), and what it filled in, as "variable <- origin" lines.
func withConnectionDefaults(hostVars map[string]any, defaults connectionDefaults) (map[string]any, []string) {
	merged := make(map[string]any, len(hostVars)+len(defaults.Vars))
	for key, value := range hostVars {
		merged[key] = value
	}
	var applied []string
	for key, value := range defaults.Vars {
		if current, set := merged[key]; set && current != nil && current != "" {
			continue
		}
		merged[key] = value
		applied = append(applied, key+" <- "+defaults.Origins[key])
	}
	sort.Strings(applied)
	return merged, applied
}

// extraVarsInventory is the inline one-host inventory the extra vars are read
// through: ansible-inventory lists a host with exactly the variables Ansible
// layers over it, so the host's variables are the extra vars of the run and
// nothing else (extraVarsHost is the name Ansible gives that host).
const (
	extraVarsInventory = "localhost,"
	extraVarsHost      = "localhost"
)

// keepValuesOutOfAnsibleLog makes the Ansible command write no controller log.
// ansible-inventory --list with a vault or an `-e @file` prints the decrypted
// value of every variable on every host, and with the runtime's ANSIBLE_LOG_PATH
// the whole document lands in ansible.log in clear text: the log's redaction
// masks only keys that are named like a secret (password, token, ...), so a
// credential kept under another name would stay. /dev/null is the value that
// switches the log off for the command and still wins over a log_path of
// ansible.cfg; an empty value would make Ansible warn that the path is a
// directory (ansible-core 2.19.2). Call it before ansible.HoldCommandLog, which
// reads the log path of the command's environment.
func keepValuesOutOfAnsibleLog(command *exec.Cmd) {
	if command.Env == nil {
		command.Env = os.Environ()
	}
	// The last entry wins, as for exec.Cmd and ansible.LogPathFromEnv.
	command.Env = append(command.Env, "ANSIBLE_LOG_PATH="+os.DevNull)
}

// loadEffectiveTargetGroup is the pattern the identity playbooks' `hosts:`
// resolves to: the target_group the playbook run is going to see, or the default.
//
// Only an extra var counts. Ansible templates a play's `hosts:` with the extra
// vars (and the play's own vars), not with the inventory's variables: a
// target_group set under `all: vars:` or in a host's host_vars shows up in
// `ansible-inventory --list` on every host, and the play still runs on
// `freeipa-server` (checked with ansible-playbook --list-hosts, ansible-core
// 2.19.2). Reading it from the merged host variables would lock a host the
// playbook does not run on. So the value is read from the extra-vars layer alone:
// extraArgs (the -e and vault arguments the playbook is handed) run through an
// inline one-host inventory, with the inventory's group_vars and host_vars
// (including those of the working directory) and the inventory plugins other
// than the host list switched off. `-e key=value`, JSON and `@file` all work,
// as does an encrypted file when ansible-inventory can read its vault password.
// With no arguments the answer is the default and Ansible is not asked.
//
// A value that is not a plain pattern leaves no answer for what the playbook
// will run on, so it is an error, as is anything that keeps Ansible from
// reading the arguments.
func loadEffectiveTargetGroup(ctx context.Context, extraArgs []string) (string, error) {
	if len(extraArgs) == 0 {
		return identityDefaultTargetGroup, nil
	}
	args := append([]string{"-i", extraVarsInventory, "--list"}, extraArgs...)
	command := deployAnsibleCommand(ctx, "ansible-inventory", args...)
	if slices.Contains(extraArgs, "--ask-vault-pass") {
		// The only prompt that can come from this command, as in
		// loadDeployInventorySnapshotWithArgs.
		command.Stdin = os.Stdin
	}
	keepValuesOutOfAnsibleLog(command)
	command.Env = append(command.Env,
		// No group_vars or host_vars: the working directory of a workspace has them.
		"ANSIBLE_VARS_ENABLED=",
		// The inline host list must be parsed, whatever the environment enables.
		"ANSIBLE_INVENTORY_ENABLED=host_list",
	)
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	release, err := ansible.HoldCommandLog(ctx, command)
	if err == nil {
		err = command.Run()
		release()
	}
	if err != nil {
		return "", fmt.Errorf("ansible-inventory --list (extra vars only): %w: %s", childproc.Cause(ctx, err), strings.TrimSpace(stderr.String()))
	}
	var doc struct {
		Meta struct {
			HostVars map[string]map[string]any `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		return "", fmt.Errorf("parse ansible-inventory output (extra vars only): %w", err)
	}
	for host := range doc.Meta.HostVars {
		if host != extraVarsHost {
			return "", fmt.Errorf("ansible-inventory (extra vars only) listed host %q; only %q is expected, so it is not the document this reads", host, extraVarsHost)
		}
	}
	return targetGroupFromExtraVars(doc.Meta.HostVars[extraVarsHost])
}

// targetGroupFromExtraVars is the pattern the `hosts:` of the identity
// playbooks resolves to given the extra vars of the run: their target_group, or
// the default when none sets it. A value that is not a non-empty string, or that
// starts with `-` and so is not a host pattern, is an error.
func targetGroupFromExtraVars(extraVars map[string]any) (string, error) {
	value, set := extraVars["target_group"]
	if !set || value == nil {
		return identityDefaultTargetGroup, nil
	}
	group, isString := value.(string)
	if !isString || strings.TrimSpace(group) == "" {
		return "", fmt.Errorf("extra vars 的 target_group 是 %v(%T)；它必須是非空的字串 pattern，否則無法確定 playbook 會對哪些主機執行", value, value)
	}
	group = strings.TrimSpace(group)
	if strings.HasPrefix(group, "-") {
		return "", fmt.Errorf("target_group %q 以 - 開頭，不是主機 pattern", group)
	}
	return group, nil
}
