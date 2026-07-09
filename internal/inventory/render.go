package inventory

import (
	"fmt"
	"sort"
	"strings"
)

// Render serializes hf back into the simple "host → roles" source
// format Parse reads (see hosts.example.yml) — the inverse of Parse,
// used by `pilot edit` to save a session's changes. It always
// succeeds; validation is Lint's job, not Render's, so a draft with
// lint errors (e.g. a still-empty ansible_host) can still be saved
// and edited further.
//
// Render does not preserve comments — any hand-written commentary in
// the original file (like hosts.example.yml's onboarding banner) is
// lost once a file has been round-tripped through an editing session.
func Render(hf *HostsFile) (string, error) {
	if hf == nil {
		return "", fmt.Errorf("inventory: nil source file")
	}

	var sb strings.Builder
	if len(hf.Vars) > 0 {
		sb.WriteString("vars:\n")
		for _, k := range sortedKeys(hf.Vars) {
			fmt.Fprintf(&sb, "  %s: %s\n", k, quoteScalar(hf.Vars[k]))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("hosts:\n")
	names := make([]string, len(hf.Hosts))
	byName := make(map[string]Host, len(hf.Hosts))
	for i, h := range hf.Hosts {
		names[i] = h.Name
		byName[h.Name] = h
	}
	sort.Strings(names)

	for _, name := range names {
		h := byName[name]
		fmt.Fprintf(&sb, "  %s:\n", h.Name)
		if h.AnsibleHost != "" {
			fmt.Fprintf(&sb, "    ansible_host: %s\n", quoteScalar(h.AnsibleHost))
		}
		if h.AnsibleUser != "" {
			fmt.Fprintf(&sb, "    ansible_user: %s\n", quoteScalar(h.AnsibleUser))
		}
		if h.SSHKeyFile != "" {
			fmt.Fprintf(&sb, "    ansible_ssh_private_key_file: %s\n", quoteScalar(h.SSHKeyFile))
		}
		for _, k := range sortedKeys(h.Extra) {
			fmt.Fprintf(&sb, "    %s: %s\n", k, quoteScalar(h.Extra[k]))
		}
		if len(h.Roles) > 0 {
			fmt.Fprintf(&sb, "    roles: [%s]\n", strings.Join(h.Roles, ", "))
		} else {
			sb.WriteString("    roles: []\n")
		}
		if h.Env != "" {
			fmt.Fprintf(&sb, "    env: %s\n", quoteScalar(h.Env))
		}
	}

	return sb.String(), nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
