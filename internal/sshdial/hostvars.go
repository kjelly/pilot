package sshdial

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Host variables that change the SSH connection and that pilot's own ssh
// does not support: it refuses them rather than connect differently from
// Ansible (docs/superpowers/specs/2026-10-30-freeipa-go-reconcile-phase1-spec.md
// §4). Both the Go engine's tunnel and the identity lock derive their Target
// through TargetFromHostVars, so the same inventory is accepted or refused
// the same way by both (AGENTS.md §5.7: one source for the rule).
var unsupportedSSHHostVars = []string{
	"ansible_password", "ansible_ssh_pass", "ansible_ssh_password",
	"ansible_ssh_host", "ansible_ssh_port", "ansible_ssh_user",
	"ansible_private_key_file", "ansible_ssh_executable",
}

// multiplexOptions are the only options ansible_ssh_args may carry: they
// tune Ansible's connection reuse, which pilot's ssh does on its own (it
// always runs with ControlPath=none).
var multiplexOptions = map[string]bool{"ControlMaster": true, "ControlPath": true, "ControlPersist": true}

// TargetFromHostVars builds the SSH Target of an inventory host from its
// effective host variables (ansible-inventory --list). host is the inventory
// name: it is the connection address only when ansible_host does not say
// otherwise, never the host's identity (AGENTS.md §5.13).
//
// Anything pilot's ssh cannot honor is an error that names the variable:
// a password, ProxyCommand and any `-o` outside the allowlist of Target,
// an ansible_connection other than ssh (docker, local, ...), an
// ansible_ssh_executable. The caller must not fall back to running without
// the connection it could not describe.
func TargetFromHostVars(host string, vars map[string]any) (Target, error) {
	var t Target
	for _, key := range unsupportedSSHHostVars {
		if v, ok := vars[key]; ok && v != nil && v != "" {
			return t, fmt.Errorf("%s 設定了 %s；不支援", host, key) // gate: ssh-unsupported-var
		}
	}
	if c, ok := vars["ansible_connection"]; ok && c != nil && c != "ssh" {
		return t, fmt.Errorf("%s 的 ansible_connection 是 %v；只支援 ssh", host, c) // gate: ssh-connection
	}
	t.Host = host
	// A value of another type is refused, not ignored: ignoring ansible_user
	// 1000 would connect as the local user (spec §4).
	for _, field := range []struct {
		key  string
		into *string
	}{{"ansible_host", &t.Host}, {"ansible_user", &t.User}, {"ansible_ssh_private_key_file", &t.IdentityFile}} {
		v, ok := vars[field.key]
		if !ok || v == nil {
			continue
		}
		s, isString := v.(string)
		if !isString {
			return t, fmt.Errorf("%s 的 %s 是 %T，不是字串；不猜測它的意思", host, field.key, v) // gate: ssh-var-type
		}
		switch {
		case field.key == "ansible_host" && s == "":
			// An empty address keeps the inventory name.
		case field.key == "ansible_ssh_private_key_file":
			*field.into = expandHome(s)
		default:
			*field.into = s
		}
	}
	if p, ok := vars["ansible_port"]; ok && p != nil {
		port, err := strconv.Atoi(fmt.Sprint(p))
		if err != nil {
			return t, fmt.Errorf("%s 的 ansible_port %v 不是整數", host, p) // gate: ssh-port
		}
		t.Port = port
	}
	t.Options = map[string]string{}
	for _, key := range []string{"ansible_ssh_common_args", "ansible_ssh_extra_args"} {
		opts, err := sshOptionArgs(vars[key])
		if err != nil {
			return t, fmt.Errorf("%s 的 %s：%w", host, key, err) // gate: ssh-extra-args
		}
		for k, v := range opts {
			t.Options[k] = v
		}
	}
	opts, err := sshOptionArgs(vars["ansible_ssh_args"])
	if err != nil {
		return t, fmt.Errorf("%s 的 ansible_ssh_args：%w", host, err) // gate: ssh-args-parse
	}
	for k := range opts {
		if !multiplexOptions[k] {
			return t, fmt.Errorf("%s 的 ansible_ssh_args 含 %s；只接受 ControlMaster、ControlPath、ControlPersist", host, k) // gate: ssh-args-mux
		}
	}
	if err := t.Validate(); err != nil {
		return t, fmt.Errorf("%s：%w", host, err) // gate: ssh-validate
	}
	return t, nil
}

// expandHome resolves a leading "~" or "~/" the way a login shell would:
// ansible's own file lookups expand it, while the value reaches ssh as one
// argv entry no shell sees.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

// sshOptionArgs reads "-o Key=Value" arguments; anything else is refused.
func sshOptionArgs(v any) (map[string]string, error) {
	out := map[string]string{}
	if v == nil || v == "" {
		return out, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("不是字串") // gate: opts-not-string
	}
	words, err := splitShellWords(s)
	if err != nil {
		return nil, err // gate: opts-split
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		var opt string
		switch {
		case w == "-o" && i+1 < len(words):
			i++
			opt = words[i]
		case strings.HasPrefix(w, "-o") && len(w) > 2:
			opt = w[2:]
		default:
			return nil, fmt.Errorf("只接受 -o Key=Value，不接受 %q", w) // gate: opts-not-dash-o
		}
		key, value, ok := strings.Cut(opt, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("-o %q 不是 Key=Value", opt) // gate: opts-not-key-value
		}
		out[key] = value
	}
	return out, nil
}

// splitShellWords splits on blanks, honoring single and double quotes.
func splitShellWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words, inWord = append(words, cur.String()), false
				cur.Reset()
			}
		case r == '\\':
			return nil, fmt.Errorf("不支援反斜線跳脫") // gate: split-backslash
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("引號沒有成對") // gate: split-quote
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
