package inventory

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Host is one machine from the source file, after normalizing its
// YAML mapping into typed fields plus a passthrough Extra bag.
type Host struct {
	Name        string
	AnsibleHost string
	AnsibleUser string
	SSHKeyFile  string
	Roles       []string
	Env         string
	Extra       map[string]string // preserved as strings for stable, quoted YAML output
}

// HostsFile is the parsed simple source file: `vars:` (fleet-wide
// connection defaults, same semantics as inventory `all.vars`) plus
// `hosts:` (one entry per machine).
type HostsFile struct {
	Vars  map[string]string
	Hosts []Host
}

// rawHostsFile mirrors the YAML shape before typed extraction —
// map[string]interface{} because a host entry mixes known scalar
// fields with an open-ended set of passthrough vars.
type rawHostsFile struct {
	Vars  map[string]string                 `yaml:"vars"`
	Hosts map[string]map[string]interface{} `yaml:"hosts"`
}

// Parse reads the simple `host → roles` source format described in
// hosts.example.yml.
func Parse(data []byte) (*HostsFile, error) {
	var raw rawHostsFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("inventory: parse source file: %w", err)
	}
	hf := &HostsFile{Vars: raw.Vars}
	names := make([]string, 0, len(raw.Hosts))
	for name := range raw.Hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fields := raw.Hosts[name]
		h := Host{Name: name, Extra: map[string]string{}}
		for k, v := range fields {
			switch k {
			case "ansible_host":
				h.AnsibleHost = fmt.Sprint(v)
			case "ansible_user":
				h.AnsibleUser = fmt.Sprint(v)
			case "ansible_ssh_private_key_file":
				h.SSHKeyFile = fmt.Sprint(v)
			case "env":
				h.Env = fmt.Sprint(v)
			case "roles":
				list, ok := v.([]interface{})
				if !ok {
					return nil, fmt.Errorf("inventory: host %q: `roles` must be a list", name)
				}
				for _, r := range list {
					h.Roles = append(h.Roles, fmt.Sprint(r))
				}
			default:
				h.Extra[k] = fmt.Sprint(v)
			}
		}
		hf.Hosts = append(hf.Hosts, h)
	}
	return hf, nil
}

// Issue is one Lint finding. Severity "error" blocks Generate;
// "warning" does not.
type Issue struct {
	Host     string
	Severity string // "error" | "warning"
	Message  string
}

func (i Issue) String() string {
	if i.Host == "" {
		return fmt.Sprintf("[%s] %s", i.Severity, i.Message)
	}
	return fmt.Sprintf("[%s] host %q: %s", i.Severity, i.Host, i.Message)
}

// Lint validates the source file against the role/env catalog.
// Rejecting unknown roles here — rather than letting them through to
// a group Ansible has never heard of — is what replaces the old
// grep-for-<FILL-ME>-at-preflight-time safety net with a check that
// runs before anything is ever rendered.
func Lint(hf *HostsFile) []Issue {
	var issues []Issue
	if hf == nil {
		return issues
	}
	validRoles := validRoleNames()
	validEnvs := validEnvNames()
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		if seen[h.Name] {
			issues = append(issues, Issue{h.Name, "error", "duplicate host name"})
		}
		seen[h.Name] = true

		if h.AnsibleHost == "" {
			issues = append(issues, Issue{h.Name, "error", "ansible_host is empty"})
		} else if strings.Contains(h.AnsibleHost, "<FILL-ME>") {
			issues = append(issues, Issue{h.Name, "error", "ansible_host still has a <FILL-ME> placeholder"})
		}

		if len(h.Roles) == 0 {
			issues = append(issues, Issue{h.Name, "warning", "no roles assigned — this host won't be targeted by any playbook"})
		}
		roleSeen := map[string]bool{}
		for _, r := range h.Roles {
			if !validRoles[r] {
				issues = append(issues, Issue{h.Name, "error", fmt.Sprintf("unknown role %q (see `pilot inventory roles`)", r)})
				continue
			}
			if roleSeen[r] {
				issues = append(issues, Issue{h.Name, "warning", fmt.Sprintf("role %q listed more than once", r)})
			}
			roleSeen[r] = true
		}

		if h.Env != "" && !validEnvs[h.Env] {
			issues = append(issues, Issue{h.Name, "error", fmt.Sprintf("unknown env %q (must be one of prod|staging|sandbox, or omitted)", h.Env)})
		}
	}
	return issues
}

// HasErrors reports whether any issue is severity "error".
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

// Generate expands the source file into the full nested Ansible
// inventory YAML. It refuses to render over lint errors — same
// "reject rather than silently drop" stance as
// internal/spec.GenerateInventory — so a bad source file fails at
// generate time, not at ansible-playbook run time.
func Generate(hf *HostsFile) (string, error) {
	if hf == nil {
		return "", fmt.Errorf("inventory: nil source file")
	}
	if issues := Lint(hf); HasErrors(issues) {
		var b strings.Builder
		b.WriteString("inventory: refusing to generate, fix these first:\n")
		for _, i := range issues {
			if i.Severity == "error" {
				fmt.Fprintf(&b, "  - %s\n", i)
			}
		}
		return "", fmt.Errorf("%s", b.String())
	}

	byRole := map[string][]string{}
	byEnv := map[string][]string{}
	for _, h := range hf.Hosts {
		for _, r := range h.Roles {
			byRole[r] = append(byRole[r], h.Name)
		}
		if h.Env != "" {
			byEnv[h.Env] = append(byEnv[h.Env], h.Name)
		}
	}
	for _, list := range byRole {
		sort.Strings(list)
	}
	for _, list := range byEnv {
		sort.Strings(list)
	}

	var sb strings.Builder
	sb.WriteString("---\n")
	sb.WriteString("all:\n")

	sb.WriteString("  hosts:\n")
	for _, h := range hf.Hosts {
		fmt.Fprintf(&sb, "    %s:\n", h.Name)
		if h.AnsibleHost != "" {
			fmt.Fprintf(&sb, "      ansible_host: %s\n", quoteScalar(h.AnsibleHost))
		}
		if h.AnsibleUser != "" {
			fmt.Fprintf(&sb, "      ansible_user: %s\n", quoteScalar(h.AnsibleUser))
		}
		if h.SSHKeyFile != "" {
			fmt.Fprintf(&sb, "      ansible_ssh_private_key_file: %s\n", quoteScalar(h.SSHKeyFile))
		}
		extraKeys := make([]string, 0, len(h.Extra))
		for k := range h.Extra {
			extraKeys = append(extraKeys, k)
		}
		sort.Strings(extraKeys)
		for _, k := range extraKeys {
			fmt.Fprintf(&sb, "      %s: %s\n", k, quoteScalar(h.Extra[k]))
		}
	}

	if len(hf.Vars) > 0 {
		sb.WriteString("  vars:\n")
		varKeys := make([]string, 0, len(hf.Vars))
		for k := range hf.Vars {
			varKeys = append(varKeys, k)
		}
		sort.Strings(varKeys)
		for _, k := range varKeys {
			fmt.Fprintf(&sb, "    %s: %s\n", k, quoteScalar(hf.Vars[k]))
		}
	}

	sb.WriteString("  children:\n")
	for _, name := range topLevelOrder {
		if children := aggregateChildren(name); children != nil {
			fmt.Fprintf(&sb, "    %s:\n", name)
			sb.WriteString("      children:\n")
			for _, c := range children {
				writeGroupHosts(&sb, c, byRole[c], 4, name == "infra-provider")
			}
			continue
		}
		writeGroupHosts(&sb, name, byRole[name], 2, false)
	}
	for _, name := range envOrder {
		writeGroupHosts(&sb, name, byEnv[name], 2, false)
	}

	return sb.String(), nil
}

// writeGroupHosts renders one group entry at the given indent depth
// (in 2-space units). omitHosts renders a bare child reference (used
// inside infra-provider, whose children are already rendered as
// their own top-level groups — Ansible merges membership from there).
func writeGroupHosts(sb *strings.Builder, name string, hosts []string, indent int, omitHosts bool) {
	pad := strings.Repeat("  ", indent)
	if omitHosts {
		fmt.Fprintf(sb, "%s%s:\n", pad, name)
		return
	}
	fmt.Fprintf(sb, "%s%s:\n", pad, name)
	if len(hosts) == 0 {
		fmt.Fprintf(sb, "%s  hosts: {}\n", pad)
		return
	}
	fmt.Fprintf(sb, "%s  hosts:\n", pad)
	for _, h := range hosts {
		fmt.Fprintf(sb, "%s    %s:\n", pad, h)
	}
}

func quoteScalar(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
