package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_DcgmExporterSpec locks the structure of
// docs/verification/dcgm-exporter.md (v1.0 — NVIDIA dcgm-exporter GPU
// metrics agent, installed as the official Docker image via the NVIDIA
// Container Toolkit's `nvidia` docker runtime, with mandatory HTTP Basic
// Auth — the docker-based sibling of host-monitoring.md's binary-based
// node_exporter):
//
//	C1  nvidia-container-toolkit installed (nvidia-ctk CLI present)
//	C2  docker daemon has the nvidia runtime registered
//	C3  pilot-dcgm-exporter container is running
//	C4  container image matches the pinned version tag
//	C5  container is wired to the nvidia docker runtime
//	C6  GPU is actually reachable from inside the container (nvidia-smi -L)
//	C7  9400/tcp is listening
//	C8  an UNauthenticated request to /metrics (9400) is rejected (401)
//	C9  web-config.yml declares basic_auth_users for the configured user
//
// Cross-row invariants locked below:
//
//   - No row may use ~active (matches inactive as a substring).
//   - dcgm-exporter-apply.yml must install via the official Docker image
//     (no pinned-binary get_url path exists for this exporter — it links
//     libdcgm.so, unlike node_exporter), using community.docker.docker_container.
//   - The container must run with runtime: nvidia (GPU passthrough).
//   - GPU presence must be gated on nvidia-smi -L succeeding BEFORE any
//     OS/arch/secret gate fires, mirroring host-monitoring-apply.yml's
//     port-occupied-by-other gate ordering — a host with no GPU is out of
//     scope, not a failure.
//   - A "port already served by something we don't manage" gate (NVIDIA
//     GPU Operator DaemonSet) must exist, modeled on host-monitoring's
//     Kubernetes DaemonSet detection, and must require BOTH the port
//     listening AND our own container not being the one bound to it.
//   - The basic-auth password must be a hard-required gate, no escape
//     hatch, gated only on GPU-present-and-not-occupied.
//   - The bcrypt hash must be generated via htpasswd, gated on a
//     change-detection fingerprint of the plaintext, not regenerated every
//     apply (bcrypt salts are non-deterministic per call).
//   - The plaintext password must never be logged (no_log on every task
//     that touches it).
//   - The container restart must be idempotency-gated on the web-config
//     actually changing, never run unconditionally.
//   - The GPU/port/own-container read-only probes must set
//     check_mode: false — command/shell modules have no check-mode
//     simulation, so ansible-core skips them under --check and
//     synthesizes a fake rc=0/stdout="" result; without this override
//     every --check --diff dry-run would misreport "GPU present" and
//     "port occupied by other" regardless of the real host (found by
//     running --check against a real GPU host during development).
func TestRegression_DcgmExporterSpec(t *testing.T) {
	const specPath = "../../docs/verification/dcgm-exporter.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based checks", r.ID)
		}
	}

	// C3 must be an rc/count-based container-running check.
	if !strings.Contains(cmd["C3"], "docker ps") || !strings.Contains(cmd["C3"], "status=running") {
		t.Errorf("C3 must check docker ps --filter status=running, got %q", cmd["C3"])
	}

	// C4 must pin the version tag (image version drift check).
	if !strings.HasPrefix(exp["C4"], "~nvidia/dcgm-exporter:") {
		t.Errorf("C4 expected must pin the nvidia/dcgm-exporter image tag, got %q", exp["C4"])
	}

	// C1/C4/C5 must NOT use Docker's own Go-template `-f`/`--format
	// '{{...}}'` syntax — ansible ad-hoc runs the Command string through
	// Jinja finalization, and a leading-dot token like `{{.Config.Image}}`
	// is a Jinja syntax error (module_error, same trap as dashboard.md
	// C14; confirmed by a live pilot-verify run during development).
	for _, id := range []string{"C1", "C4", "C5"} {
		if strings.Contains(cmd[id], "{{") || strings.Contains(cmd[id], "}}") {
			t.Errorf("%s must not contain Docker Go-template braces {{...}} — ansible ad-hoc Jinja-finalizes the Command string (module_error), got %q", id, cmd[id])
		}
	}
	if strings.Contains(cmd["C1"], "command -v") {
		t.Errorf("C1 must not use `command -v` (a shell builtin) with a non-shell command module, got %q", cmd["C1"])
	}

	// C5 must check the runtime is nvidia (config claim); C6 must prove GPU
	// access actually works from inside the container (behavior proof) —
	// same "config vs. behavior" split as host-monitoring's C9/C10.
	if !strings.Contains(cmd["C5"], "docker inspect") || !strings.Contains(cmd["C5"], "Runtime") {
		t.Errorf("C5 must inspect the container's Runtime, got %q", cmd["C5"])
	}
	if !strings.Contains(cmd["C6"], "docker exec") || !strings.Contains(cmd["C6"], "nvidia-smi") {
		t.Errorf("C6 must exec nvidia-smi inside the container (behavior proof, not just config), got %q", cmd["C6"])
	}
	if exp["C6"] != "0" {
		t.Errorf("C6 expected must be rc-based `0`, got %q", exp["C6"])
	}

	// C8 must assert on 401 specifically (auth actually enforced), hitting
	// the real metrics endpoint on the contract's port, WITHOUT credentials.
	if !strings.Contains(cmd["C8"], ":9400/metrics") {
		t.Errorf("C8 must hit :9400/metrics, got %q", cmd["C8"])
	}
	if strings.Contains(cmd["C8"], "-u ") || strings.Contains(cmd["C8"], "://prometheus:") {
		t.Errorf("C8 must be an UNauthenticated request (no credentials), got %q", cmd["C8"])
	}
	if exp["C8"] != "~401" {
		t.Errorf("C8 expected must be ~401, got %q", exp["C8"])
	}

	// C9 must assert the web-config.yml declares basic_auth_users for the
	// configured user.
	if !strings.Contains(cmd["C9"], "web-config.yml") || !strings.Contains(cmd["C9"], "prometheus:") {
		t.Errorf("C9 must check web-config.yml for the configured basic-auth user, got %q", cmd["C9"])
	}
	if exp["C9"] != "0" {
		t.Errorf("C9 expected must be rc-based `0`, got %q", exp["C9"])
	}

	// No credentials belong in a spec (AGENTS.md).
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"password=", "-u prometheus:", "secret_key"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	// C8 is verify-only (see contracts/dcgm-exporter.yaml exemptions) —
	// derived from C3+C9, not its own mutation task.
	for _, id := range wantIDs {
		if id == "C8" {
			continue
		}
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/dcgm-exporter-apply.yml")
	if err != nil {
		t.Fatalf("read dcgm-exporter-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// Must install via the official Docker image (no pinned-binary path
	// exists for this exporter — it links libdcgm.so).
	if !strings.Contains(applyRaw, "community.docker.docker_container") {
		t.Errorf("dcgm-exporter-apply.yml must run dcgm-exporter via community.docker.docker_container")
	}
	if !strings.Contains(applyRaw, "image: \"nvidia/dcgm-exporter:") {
		t.Errorf("dcgm-exporter-apply.yml must use the official nvidia/dcgm-exporter image")
	}
	if !strings.Contains(applyRaw, "runtime: nvidia") {
		t.Errorf("dcgm-exporter-apply.yml container task must set runtime: nvidia (GPU passthrough)")
	}

	// GPU detection must gate everything else, evaluated before any
	// OS/arch/secret gate.
	if !strings.Contains(applyRaw, "nvidia-smi -L") {
		t.Errorf("dcgm-exporter-apply.yml must detect a usable GPU via nvidia-smi -L")
	}

	// The GPU/port/own-container read-only probes must force real
	// execution under --check (check_mode: false) — otherwise ansible-core
	// skips command/shell tasks under --check and synthesizes a fake
	// rc=0/stdout="" result, which would make every dry-run misreport "GPU
	// present" and "port occupied by other" regardless of the real host.
	for _, probe := range []string{
		"Detect a working NVIDIA GPU + driver (nvidia-smi -L)",
		"Check whether {{ dcgm_exporter_port }}/tcp is already listening",
		"Check whether our own {{ dcgm_exporter_container_name }} container is already running",
	} {
		probeIdx := strings.Index(applyRaw, probe)
		if probeIdx < 0 {
			t.Fatalf("dcgm-exporter-apply.yml missing expected probe task %q", probe)
		}
		probeBlock := applyRaw[probeIdx : probeIdx+500]
		if !strings.Contains(probeBlock, "check_mode: false") {
			t.Errorf("probe %q must set check_mode: false so --check dry-runs reflect the real host, not a synthesized rc=0/stdout=\"\", got:\n%s", probe, probeBlock)
		}
	}
	gpuFactIdx := strings.Index(applyRaw, "dcgm_exporter_gpu_present:")
	osGateIdx := strings.Index(applyRaw, "Gate: supported OS")
	if gpuFactIdx < 0 || osGateIdx < 0 || gpuFactIdx > osGateIdx {
		t.Fatalf("dcgm_exporter_gpu_present must be computed before the OS gate")
	}
	for _, gate := range []string{
		"Gate: supported OS",
		"Gate: supported CPU architecture",
		"Gate: required basic-auth password present",
	} {
		gateIdx := strings.Index(applyRaw, gate)
		if gateIdx < 0 {
			t.Fatalf("dcgm-exporter-apply.yml missing expected gate %q", gate)
		}
		gateBlock := applyRaw[gateIdx : gateIdx+700]
		if !strings.Contains(gateBlock, "when: dcgm_exporter_gpu_present and not dcgm_exporter_port_occupied_by_other") {
			t.Errorf("gate %q must be skipped unless dcgm_exporter_gpu_present and not occupied-by-other, got:\n%s", gate, gateBlock)
		}
	}

	// The entire install block must be skipped wholesale unless GPU present
	// and not occupied-by-other.
	blockIdx := strings.Index(applyRaw, `"dcgm-exporter install + container"`)
	if blockIdx < 0 {
		t.Fatalf("dcgm-exporter-apply.yml missing the main install block")
	}
	if !strings.Contains(applyRaw[blockIdx:blockIdx+250], "when: dcgm_exporter_gpu_present and not dcgm_exporter_port_occupied_by_other") {
		t.Errorf("the main install block must be gated on dcgm_exporter_gpu_present and not dcgm_exporter_port_occupied_by_other")
	}

	// Kubernetes GPU Operator / foreign-exporter detection: the port check
	// must require BOTH listening AND not our own container.
	if !strings.Contains(applyRaw, "ss -ltn") {
		t.Errorf("dcgm-exporter-apply.yml must check whether dcgm_exporter_port is already listening (ss -ltn)")
	}
	occupiedIdx := strings.Index(applyRaw, "dcgm_exporter_port_occupied_by_other:")
	if occupiedIdx < 0 {
		t.Fatalf("dcgm-exporter-apply.yml must compute a dcgm_exporter_port_occupied_by_other fact")
	}
	occupiedExpr := applyRaw[occupiedIdx : occupiedIdx+350]
	if !strings.Contains(occupiedExpr, "dcgm_exporter_port_check.rc") || !strings.Contains(occupiedExpr, "dcgm_exporter_own_container_check.stdout") {
		t.Errorf("dcgm_exporter_port_occupied_by_other must require BOTH the port listening AND our own container not being the one bound to it, got %q", occupiedExpr)
	}

	// The basic-auth password must be a hard-required gate, no escape hatch.
	if !strings.Contains(applyRaw, "dcgm_exporter_basic_auth_password is defined") {
		t.Errorf("dcgm-exporter-apply.yml must gate on dcgm_exporter_basic_auth_password being defined — auth is mandatory, not optional")
	}

	// Steps that depend on htpasswd's real .stdout (only simulated under
	// --check, since Step 3's package install itself isn't check-mode
	// forced) must defer to the real apply, same convention as
	// host-monitoring-apply.yml's Step 8/9 — otherwise a --check dry-run
	// on a from-scratch host crashes trying to .split() an empty stdout.
	for _, step := range []string{
		`when: dcgm_exporter_basic_auth_changed and not ansible_check_mode`,
	} {
		if strings.Count(applyRaw, step) < 3 {
			t.Errorf("dcgm-exporter-apply.yml must gate the htpasswd-generate/webconfig-render/fingerprint-persist tasks on %q (expected at least 3 occurrences), got %d", step, strings.Count(applyRaw, step))
		}
	}

	// The bcrypt hash must come from htpasswd, gated on a change-detection
	// fingerprint, not regenerated every apply.
	if !strings.Contains(applyRaw, "apache2-utils") {
		t.Errorf("dcgm-exporter-apply.yml must install htpasswd via apache2-utils")
	}
	if !strings.Contains(applyRaw, "htpasswd -nbBC") {
		t.Errorf("dcgm-exporter-apply.yml must generate the bcrypt hash via htpasswd -nbBC")
	}
	if !strings.Contains(applyRaw, "hash('sha256')") {
		t.Errorf("dcgm-exporter-apply.yml must use a fingerprint (hash of the plaintext) to detect credential changes")
	}
	if !strings.Contains(applyRaw, "dcgm_exporter_basic_auth_changed") {
		t.Errorf("dcgm-exporter-apply.yml must gate hash regeneration/file rewrite on a computed \"credential changed\" fact")
	}

	// The container's --web-config-file must actually be wired in, not just
	// rendered to disk unused.
	if !strings.Contains(applyRaw, "--web-config-file=") {
		t.Errorf("dcgm-exporter-apply.yml container command must pass --web-config-file (auth must actually be wired in)")
	}

	// The plaintext password is referenced in a handful of expected places
	// (htpasswd command line, fingerprint computation, required-password
	// gate) — every task touching it must be no_log.
	if strings.Count(applyRaw, "no_log: true") < 4 {
		t.Errorf("dcgm-exporter-apply.yml must no_log every task that handles the plaintext password or its hash (expected at least 4 such tasks), got %d", strings.Count(applyRaw, "no_log: true"))
	}

	// The container restart must be idempotency-gated on the web-config
	// actually changing, never run unconditionally on every apply.
	restartIdx := strings.Index(applyRaw, `restart: "{{ dcgm_exporter_webconfig_result is changed }}"`)
	if restartIdx < 0 {
		t.Errorf("dcgm-exporter-apply.yml container restart must be gated on dcgm_exporter_webconfig_result is changed, not run unconditionally")
	}

	// No cap_add/capabilities escalation by default (deliberate
	// least-privilege default, see spec §5) — a comment explaining the
	// omission is fine; an actual docker_container cap_add/capabilities
	// key is not.
	if strings.Contains(applyRaw, "cap_add") || strings.Contains(applyRaw, "capabilities:") {
		t.Errorf("dcgm-exporter-apply.yml must not add container capabilities by default (spec §5 deliberate least-privilege default)")
	}
}
