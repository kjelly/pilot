package spec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This spec intentionally supports a target_group override for disposable
// multi-VM topologies, so the vm-target reference inventory is not expected to
// expose a literal pilot-access-gateway group. Alignment is owned by the
// topology inventory used by the evidence run (AGENTS.md §3 exception).
func TestRegression_PilotAccessGatewaySpec(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	wantIDs := []string{"AG01", "AG02", "AG03", "AG04", "AG06", "AG09", "AG12", "AG19", "AG30", "AG32", "AG33", "AG34", "AG41", "AG42", "AG43", "AG44", "AG81", "AG82", "AG83", "AG84", "AG85", "AG86", "AG87", "AG88", "AG89", "AG90", "AG91", "AG92", "AG93", "AG94", "AG95", "AG96", "AG97"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, row := range s.Rows {
		if row.ID != wantIDs[i] {
			t.Errorf("row[%d].ID=%q want=%q", i, row.ID, wantIDs[i])
		}
		if strings.TrimSpace(row.Expected) == "" || strings.TrimSpace(row.Command) == "" {
			t.Errorf("row %s has empty expected or command", row.ID)
		}
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Fatalf("spec lint errors:\n%s", fsToString(findings))
	}
}

func TestRegression_PilotAccessGatewayGSSAPIOnlyContract(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	rows := map[string]Row{}
	for _, row := range s.Rows {
		rows[row.ID] = row
	}
	for _, required := range []string{
		"gssapiauthentication yes",
		"gssapidelegatecredentials no",
		"preferredauthentications gssapi-with-mic",
		"batchmode yes",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"pubkeyauthentication false",
	} {
		if !strings.Contains(strings.ToLower(rows["AG32"].Command), required) {
			t.Errorf("AG32 command must enforce %q", required)
		}
	}
	for _, binary := range []string{"/usr/bin/kinit", "/usr/bin/klist", "/usr/bin/kdestroy"} {
		if !strings.Contains(rows["AG33"].Command, binary) {
			t.Errorf("AG33 command missing %s", binary)
		}
	}

	playbook, err := os.ReadFile("../../playbooks/apply/pilot-access-gateway-apply.yml")
	if err != nil {
		t.Fatalf("read playbook: %v", err)
	}
	text := strings.ToLower(string(playbook))
	for _, required := range []string{
		"gssapidelegatecredentials no",
		"preferredauthentications gssapi-with-mic",
		"batchmode yes",
		"pubkeyauthentication no",
		"kbdinteractiveauthentication no",
		"passwordauthentication no",
		"tags: [ag_config, ag32]",
		"tags: [ag33]",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("playbook missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"gssapidelegatecredentials yes",
		"kbdinteractiveauthentication yes",
		"passwordauthentication yes",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("playbook must not allow Portal SSH fallback %q", forbidden)
		}
	}
}

// AG01 checks the deployed gateway_id/gateway_scope, supplied as required
// Spec v2 inputs, instead of a hardcoded example deployment.
func TestRegression_PilotAccessGatewayAG01UsesInputs(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	if s.SchemaVersion != 2 {
		t.Fatalf("schemaVersion=%d want 2", s.SchemaVersion)
	}
	required := map[string]bool{}
	for _, in := range s.Inputs {
		required[in.Name] = in.Required
	}
	for _, name := range []string{"gateway_id", "gateway_scope"} {
		if !required[name] {
			t.Errorf("input %s must be declared and required", name)
		}
	}
	var ag01 Row
	for _, row := range s.Rows {
		if row.ID == "AG01" {
			ag01 = row
		}
	}
	for _, want := range []string{
		`"  id: $PILOT_VAR_GATEWAY_ID"`,
		`"  scope: $PILOT_VAR_GATEWAY_SCOPE"`,
		`"  target_hostgroup: pilot-target-$PILOT_VAR_GATEWAY_SCOPE"`,
	} {
		if !strings.Contains(ag01.Command, want) {
			t.Errorf("AG01 probe must match the whole config line %s", want)
		}
	}
	if strings.Contains(ag01.Command, "gpu") {
		t.Errorf("AG01 must not hardcode an example deployment: %q", ag01.Command)
	}
}

// TestRegression_PilotAccessGatewayTransportContract locks the gateway-side
// deployment invariants of the captive SSH transport (docs/superpowers/
// specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md
// §12.3-§12.5): transport defaults off, the wrapper no longer carries the
// shell TTY check (Go enforces it per state), the ForceCommand drop-in
// states AllowStreamLocalForwarding and never puts PermitUserEnvironment
// inside Match (sshd -t rejects it there), and the AG43/AG44 probes check
// exactly that.
func TestRegression_PilotAccessGatewayTransportContract(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/pilot-access-gateway-apply.yml")
	if err != nil {
		t.Fatalf("read playbook: %v", err)
	}
	playbook := string(raw)
	for _, required := range []string{
		"pilot_access_gateway_transport_enabled | default(false)",
		"            transport:\n              enabled: {{ pilot_access_gateway_effective_transport_enabled | bool | to_json }}",
		"              AllowStreamLocalForwarding no\n",
		"tags: [AG_forcecommand, AG43]",
		"tags: [AG_service, AG34, AG44]",
		"tags: [AG_config, AG01, AG41, AG42, AG94]",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("playbook missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"[ -t 0 ] || exit 1",
		"              PermitUserEnvironment",
	} {
		if strings.Contains(playbook, forbidden) {
			t.Errorf("playbook must not contain %q", forbidden)
		}
	}

	s, err := Parse("../../docs/verification/pilot-access-gateway.md")
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	rows := map[string]Row{}
	for _, row := range s.Rows {
		rows[row.ID] = row
	}
	for id, tokens := range map[string][]string{
		"AG42": {"transport:", "enabled: (true|false)"},
		"AG43": {"AllowStreamLocalForwarding no", "! grep -q PermitUserEnvironment"},
		"AG44": {"exec /usr/bin/pilot portal-session", `! grep -q "\[ -t 0 \]"`},
	} {
		for _, tok := range tokens {
			if !strings.Contains(rows[id].Command, tok) {
				t.Errorf("%s command must contain %q, got %q", id, tok, rows[id].Command)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// AG19 (stateless): the probe is run, not just read.
// ---------------------------------------------------------------------------

// ag19ServiceUnit and ag19SocketUnit are the two units pilot renders as
// `systemctl cat` prints them: a "# <path>" header per file, the file verbatim, a
// blank line between files. The text is derived from playbooks/apply/
// pilot-access-gateway-apply.yml Step 15 (the .service and .socket `content:`
// blocks, rendered with the defaults: gateway_socket_path
// /run/pilot/access-gateway.sock, pilot-gateway as user and group, the portal
// group role-pilot-portal-user, no metrics textfile) plus systemctl's header
// format, which was checked against `systemctl cat` of a stock unit with a
// drop-in on this development host (Ubuntu 26.04, systemd 259) on 2026-11-19. It
// is not a capture from a pilot-installed gateway; a capture from the VM run may
// replace it.
const ag19ServiceUnit = `# /etc/systemd/system/pilot-access-gateway.service
[Unit]
Description=Pilot Access Gateway
Requires=pilot-access-gateway.socket
After=network-online.target sssd.service
Wants=network-online.target

[Service]
Type=simple
User=pilot-gateway
Group=pilot-gateway

ExecStart=/usr/local/libexec/pilot-access-gateway serve --config /etc/pilot/access-gateway.yaml --systemd-socket

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

ReadOnlyPaths=/etc/pilot
ReadOnlyPaths=/etc/ipa

[Install]
WantedBy=multi-user.target
`

const ag19SocketUnit = `# /etc/systemd/system/pilot-access-gateway.socket
[Unit]
Description=Pilot Access Gateway Socket

[Socket]
ListenStream=/run/pilot/access-gateway.sock
SocketUser=pilot-gateway
SocketGroup=role-pilot-portal-user
SocketMode=0660
RemoveOnStop=true
RuntimeDirectory=pilot

[Install]
WantedBy=sockets.target
`

// ag19DropIn is a drop-in file as `systemctl cat` prints it after its unit.
func ag19DropIn(unit, body string) string {
	return "# /etc/systemd/system/pilot-access-gateway." + unit + ".d/override.conf\n" + body
}

// ag19Cat joins the files of one `systemctl cat` answer: a blank line between
// files, as the real command prints.
func ag19Cat(files ...string) string { return strings.Join(files, "\n") }

// ag19Systemctl is what the fake `systemctl cat` answers.
type ag19Systemctl struct {
	stdout, stderr string
	rc             int
}

// The real failure shape of `systemctl cat <existing> <missing>` (same host,
// same day): the existing unit is printed, the missing one is reported on stderr
// ("No files found for <unit>.") and the exit code is 1.
const ag19NoFilesFor = "No files found for pilot-access-gateway.socket.\n"

func ag19Answer(files ...string) ag19Systemctl { return ag19Systemctl{stdout: ag19Cat(files...)} }

// ag19Case is one run of the AG19 probe.
type ag19Case struct {
	name string
	cat  ag19Systemctl
	// dirs are paths, relative to /var/lib, that exist on the host.
	dirs []string
	// pass is the verdict the spec's own matcher must reach.
	pass bool
}

// runAG19 runs the probe of the real AG19 row with a fake systemctl first on
// PATH and the two gateway directories moved under a temp /var/lib, and returns
// the spec matcher's verdict on what it printed and returned, plus the
// systemctl invocations it made.
func runAG19(t *testing.T, row Row, c ag19Case) (Verdict, []string, string) {
	t.Helper()
	root := t.TempDir()
	varLib := filepath.Join(root, "var-lib")
	for _, d := range c.dirs {
		if err := os.MkdirAll(filepath.Join(varLib, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	probe := row.Command
	for path, moved := range map[string]string{
		"/var/lib/pilot-access-gateway": filepath.Join(varLib, "pilot-access-gateway"),
		"/var/lib/pilot/access-gateway": filepath.Join(varLib, "pilot", "access-gateway"),
	} {
		if n := strings.Count(probe, path); n != 1 {
			t.Fatalf("AG19 probe mentions %s %d times, want exactly once: the harness moves it under a temp dir by substitution:\n%s", path, n, probe)
		}
		probe = strings.ReplaceAll(probe, path, moved)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	answer := filepath.Join(root, "answer")
	if err := os.Mkdir(answer, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"stdout": c.cat.stdout, "stderr": c.cat.stderr, "rc": strconv.Itoa(c.cat.rc)} {
		if err := os.WriteFile(filepath.Join(answer, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const fake = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AG19_DIR/calls\"\ncat \"$AG19_DIR/stdout\"\ncat \"$AG19_DIR/stderr\" >&2\nexit \"$(cat \"$AG19_DIR/rc\")\"\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", probe)
	cmd.Env = append(os.Environ(), "AG19_DIR="+answer, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	rc := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("sh did not run the AG19 probe: %v", err)
		}
		rc = exitErr.ExitCode()
	}
	var calls []string
	if raw, err := os.ReadFile(filepath.Join(answer, "calls")); err == nil {
		calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	verdict := row.Expect.Eval(ProbeResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: rc})
	return verdict, calls, stdout.String() + stderr.String()
}

// TestRegression_PilotAccessGatewayAG19Stateless runs AG19's probe, as the spec
// has it, against what `systemctl cat` prints and what is on disk (kjelly/
// pilot#343). The row must fail when a gateway unit declares StateDirectory= or
// CacheDirectory= in any form systemd accepts (a flush in a drop-in, the .socket
// file, leading spaces or a tab, spaces before the =) and when `systemctl cat`
// itself fails, which an unchecked pipeline read as "no such line, PASS"; and it
// must pass on a clean gateway, on comments, and when another component keeps
// state under the shared /var/lib/pilot (the 2026-11-13 fix). Each failing case
// differs from a passing case by the one thing it names.
func TestRegression_PilotAccessGatewayAG19Stateless(t *testing.T) {
	s, err := Parse("../../docs/verification/pilot-access-gateway.md")
	if err != nil {
		t.Fatal(err)
	}
	var row Row
	for _, r := range s.Rows {
		if r.ID == "AG19" {
			row = r
		}
	}
	if row.ID == "" {
		t.Fatal("pilot-access-gateway.md has no AG19 row")
	}
	// The Expected value is what it always was: the probe's exit code is 0.
	if e := row.Expect; e.ExitCode == nil || *e.ExitCode != 0 || e.Stdout != nil || e.Stderr != nil || e.LegacyRCEcho != nil {
		t.Fatalf("AG19 must expect exactly exitCode 0, got %+v", e)
	}

	// dropIn is the clean answer with one drop-in line added to the named unit.
	dropIn := func(unit, line string) ag19Systemctl {
		files := []string{ag19ServiceUnit, ag19SocketUnit}
		switch unit {
		case "service":
			files = []string{ag19ServiceUnit, ag19DropIn(unit, "[Service]\n"+line), ag19SocketUnit}
		case "socket":
			files = []string{ag19ServiceUnit, ag19SocketUnit, ag19DropIn(unit, "[Socket]\n"+line)}
		}
		return ag19Answer(files...)
	}

	clean := ag19Answer(ag19ServiceUnit, ag19SocketUnit)
	cases := []ag19Case{
		{name: "clean units on a host without gateway state", cat: clean, pass: true},
		{name: "commented #StateDirectory=x", cat: dropIn("service", "#StateDirectory=x\n"), pass: true},
		{name: "commented ;CacheDirectory=y", cat: dropIn("service", ";CacheDirectory=y\n"), pass: true},
		{name: "commented with a leading space # StateDirectory=z", cat: dropIn("socket", "  # StateDirectory=z\n"), pass: true},
		{name: "StateDirectoryMode= alone declares no state", cat: dropIn("service", "StateDirectoryMode=0750\n"), pass: true},
		{name: "RuntimeDirectory=pilot in a drop-in", cat: dropIn("socket", "RuntimeDirectory=pilot\n"), pass: true},
		{name: "another component keeps state under the shared /var/lib/pilot", cat: clean, dirs: []string{"pilot/freeipa-dns-client/pre-apply"}, pass: true},

		{name: "StateDirectory= in the service", cat: dropIn("service", "StateDirectory=pilot-access-gateway\n")},
		{name: "StateDirectory= flushed in a drop-in", cat: dropIn("service", "StateDirectory=\n")},
		{name: "CacheDirectory= in the .socket file", cat: ag19Answer(ag19ServiceUnit, strings.Replace(ag19SocketUnit, "RuntimeDirectory=pilot\n", "RuntimeDirectory=pilot\nCacheDirectory=pilot-access-gateway\n", 1))},
		{name: "CacheDirectory= in a .socket drop-in", cat: dropIn("socket", "CacheDirectory=pilot-access-gateway\n")},
		{name: "StateDirectory= with leading spaces", cat: dropIn("service", "  StateDirectory=pilot-access-gateway\n")},
		{name: "StateDirectory= with a leading tab", cat: dropIn("service", "\tStateDirectory=pilot-access-gateway\n")},
		{name: "StateDirectory = x with spaces around the =", cat: dropIn("service", "StateDirectory = pilot-access-gateway\n")},
		{name: "CacheDirectory<tab>= x", cat: dropIn("socket", "CacheDirectory\t=\tx\n")},
		{name: "systemctl cat fails after printing the service", cat: ag19Systemctl{stdout: ag19Cat(ag19ServiceUnit), stderr: ag19NoFilesFor, rc: 1}},
		{name: "systemctl cat fails with nothing printed (neither unit is installed)", cat: ag19Systemctl{stderr: "No files found for pilot-access-gateway.service.\n", rc: 1}},
		{name: "the /var/lib/pilot-access-gateway directory exists", cat: clean, dirs: []string{"pilot-access-gateway"}},
		{name: "the /var/lib/pilot/access-gateway directory exists", cat: clean, dirs: []string{"pilot/access-gateway"}},
	}
	wantCall := "cat pilot-access-gateway.service pilot-access-gateway.socket"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verdict, calls, out := runAG19(t, row, c)
			if verdict.Pass != c.pass {
				t.Errorf("AG19 verdict pass=%v (%s), want pass=%v; probe output %q", verdict.Pass, verdict.Detail, c.pass, out)
			}
			if len(calls) != 1 || calls[0] != wantCall {
				t.Errorf("AG19 asked systemctl %q, want exactly one call %q: the units the row reads are the units pilot installs", calls, wantCall)
			}
		})
	}
}
