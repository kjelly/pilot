package sandbox

import "strings"

// SandboxMode selects how run_ansible is wired to a docker sandbox.
// Using a typed enum (instead of free-form strings) keeps the wire
// format in one place and makes future modes (podman-exec, ssh, etc.)
// a single-line addition.
type SandboxMode int

const (
	// SandboxModeUnset is the zero value. Treated as SandboxModeDocker
	// for backwards compatibility (legacy configs written before the
	// enum existed used "" to mean "docker").
	SandboxModeUnset SandboxMode = iota

	// SandboxModeDocker is the default. The host runs ansible-playbook
	// with `connection: docker` against the container. Requires the
	// host to have docker-py + community.docker installed.
	SandboxModeDocker

	// SandboxModeDockerExec routes run_ansible through `docker exec`
	// so the container runs ansible-playbook itself. Container must
	// ship its own ansible binary. No host Python deps needed.
	SandboxModeDockerExec
)

// String returns the canonical wire form used in CLI flags, config
// YAML, and audit logs. Empty string is reserved for the zero
// (unset) value so YAML can omit the field entirely.
func (m SandboxMode) String() string {
	switch m {
	case SandboxModeDocker:
		return "docker"
	case SandboxModeDockerExec:
		return "docker-exec"
	default:
		return ""
	}
}

// ParseSandboxMode normalises a user-supplied string into a
// SandboxMode. Unknown values yield SandboxModeUnset plus a
// non-nil error so callers can either fall back to default or
// surface a helpful message.
//
// Accepted aliases:
//   - "" / "docker" / "DOCKER" / "docker-conn" / "docker-connection"
//     → SandboxModeDocker (legacy: empty == docker)
//   - "docker-exec" / "DOCKER-EXEC" / "docker_exec" / "exec"
//     → SandboxModeDockerExec
func ParseSandboxMode(s string) (SandboxMode, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	switch norm {
	case "", "docker", "docker-conn", "docker-connection":
		return SandboxModeDocker, nil
	case "docker-exec", "docker_exec", "exec":
		return SandboxModeDockerExec, nil
	}
	return SandboxModeUnset, &UnknownSandboxModeError{Value: s}
}

// UnknownSandboxModeError is returned by ParseSandboxMode for values
// that don't match any known mode. The message lists the accepted
// values so the user can correct their config without reading docs.
type UnknownSandboxModeError struct{ Value string }

func (e *UnknownSandboxModeError) Error() string {
	return "sandbox: unknown mode " + strconvQuote(e.Value) +
		` (accepted: "docker", "docker-exec")`
}

// strconvQuote is a tiny local quote helper so this file doesn't
// pull in fmt/strconv just for one error message. Always uses
// Go-syntax double quotes.
func strconvQuote(s string) string {
	const lowerhex = "0123456789abcdef"
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				b.WriteString(`\x`)
				b.WriteByte(lowerhex[(r>>4)&0xf])
				b.WriteByte(lowerhex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ParseOrDefault normalises a user-supplied string into a SandboxMode.
// Unknown values fall back to SandboxModeUnset (which the executor
// treats as SandboxModeDocker — the legacy behaviour). Used at config
// load / CLI parse boundaries where we want a "best effort" parse
// without aborting startup on a typo.
//
// Use ParseSandboxMode when you need to surface the error to the user.
func ParseOrDefault(s string) SandboxMode {
	m, err := ParseSandboxMode(s)
	if err != nil {
		return SandboxModeUnset
	}
	return m
}
