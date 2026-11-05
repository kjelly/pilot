package mcpclient

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// capAdd lists capabilities added back after --cap-drop ALL. The vm-target
// run (spec §13.3) decides it; until then nothing is added back.
var capAdd []string

// dockerBase is the part of every `docker run` pilot-mcp sends.
func dockerBase(t TargetConfig, interactive bool) []string {
	args := []string{t.Docker, "run", "--rm"}
	if interactive {
		args = append(args, "-i", "--init")
	}
	args = append(args, "--pull", "never", "--log-driver", "none", "--cap-drop", "ALL")
	for _, c := range capAdd {
		args = append(args, "--cap-add", c)
	}
	args = append(args, "--security-opt", "no-new-privileges")
	if t.NetworkHost {
		args = append(args, "--network", "host")
	}
	return args
}

func envMount(t TargetConfig, name, target string, readonly bool) []string {
	spec := "type=bind,source=" + path.Join(t.EnvRoot, t.Env, name) + ",target=" + target
	if readonly {
		spec += ",readonly"
	}
	return []string{"--mount", spec}
}

// sessionCommand is the container command for one MCP session. It mounts
// only the profile's environment: its .vault read-only and its data dir.
func sessionCommand(t TargetConfig, image, mode string) []string {
	args := dockerBase(t, true)
	args = append(args, envMount(t, ".vault", mcpwire.ContainerVaultDir, true)...)
	args = append(args, envMount(t, ".pilot-data", mcpwire.ContainerDataDir, false)...)
	args = append(args, "--entrypoint", mcpwire.ContainerPilotBinary, image,
		"mcp", "remote", "session", "--protocol", mcpwire.ProtocolFlag, "--mode", mode, "--env", t.Env)
	return args
}

// changesCommand exports an ended edit session; it needs only the data dir.
func changesCommand(t TargetConfig, image, sessionID string) []string {
	args := dockerBase(t, false)
	args = append(args, envMount(t, ".pilot-data", mcpwire.ContainerDataDir, false)...)
	args = append(args, "--entrypoint", mcpwire.ContainerPilotBinary, image,
		"mcp", "remote", "changes", "--protocol", mcpwire.ProtocolFlag, "--env", t.Env, sessionID)
	return args
}

// versionCommand asks the image which protocol its pilot speaks.
func versionCommand(t TargetConfig, image string) []string {
	args := dockerBase(t, false)
	args = append(args, "--entrypoint", mcpwire.ContainerPilotBinary, image, "mcp", "remote", "version")
	return args
}

// shellJoin quotes every token for the remote POSIX login shell. Tokens
// come from validated profile fields and constants; one containing a
// quote is refused rather than escaped.
func shellJoin(argv []string) (string, error) {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, "'\x00\n") {
			return "", fmt.Errorf("refusing to quote argument %s", strconv.Quote(a))
		}
		quoted[i] = "'" + a + "'"
	}
	return strings.Join(quoted, " "), nil
}

// sshArgs are the fixed ssh options (spec §5.4 step 5) plus the remote
// command; nothing user-supplied besides the validated host and config.
func sshArgs(p Profile, sshConfig, remote string) []string {
	args := []string{"-T", "-e", "none",
		"-o", "BatchMode=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "RemoteCommand=none", "-o", "RequestTTY=no",
		"-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=" + strconv.Itoa(p.Timeouts.SSHSeconds)}
	if sshConfig != "" {
		args = append(args, "-F", sshConfig)
	}
	return append(args, p.Target.SSHHost, remote)
}
