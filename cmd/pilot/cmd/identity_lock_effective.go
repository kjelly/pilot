package cmd

import (
	"context"
	"encoding/json"
	"fmt"
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

// effectiveTargetGroup is the pattern the identity playbooks' `hosts:` resolves
// to: the target_group the playbook run is going to see, or the default. It is
// read from the effective host variables (extra vars show up in every host's),
// so a target_group that arrives through `-e @file` counts like `-e
// target_group=x`. Hosts that disagree, or a value that is not a plain pattern,
// leave no single answer for what the playbook will run on, so they are errors.
func effectiveTargetGroup(hostVars map[string]map[string]any) (string, error) {
	values := map[string]bool{}
	for host, vars := range hostVars {
		value, set := vars["target_group"]
		if !set || value == nil {
			continue
		}
		group, isString := value.(string)
		if !isString || strings.TrimSpace(group) == "" {
			return "", fmt.Errorf("%s 的 target_group 是 %v(%T)；它必須是非空的字串 pattern，否則無法確定 playbook 會對哪些主機執行", host, value, value)
		}
		values[strings.TrimSpace(group)] = true
	}
	groups := make([]string, 0, len(values))
	for group := range values {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	switch len(groups) {
	case 0:
		return identityDefaultTargetGroup, nil
	case 1:
		if strings.HasPrefix(groups[0], "-") {
			return "", fmt.Errorf("target_group %q 以 - 開頭，不是主機 pattern", groups[0])
		}
		return groups[0], nil
	default:
		return "", fmt.Errorf("各主機的 target_group 不一致(%s)；無法確定 playbook 會對哪些主機執行", strings.Join(groups, "、"))
	}
}
