package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/evidence"
)

// --evidence-record and its companions are shared by `vm-target test` and
// `vm-target topology test`. The record is the machine-generated part of an
// actual-run evidence record (docs/actual-run-evidence.md §3): the operator
// adds only the failure-path arms and the limits.
var (
	vtEvidenceRecord    string
	vtEvidenceCandidate string
	vtEvidenceTree      string
	vtEvidenceRunID     string
	vtEvidenceOperator  string
)

func addEvidenceFlags(c *cobra.Command) {
	c.Flags().StringVar(&vtEvidenceRecord, "evidence-record", "", "write the machine-generated actual-run record to this Markdown file (rewritten in place; its directory's LATEST.md is updated on success)")
	c.Flags().StringVar(&vtEvidenceCandidate, "evidence-candidate", "", "tested commit SHA for the record when the run root is not a Git work tree (a `git archive` copy)")
	c.Flags().StringVar(&vtEvidenceTree, "evidence-tree", "", "tested tree id for the record when the run root is not a Git work tree")
	c.Flags().StringVar(&vtEvidenceRunID, "evidence-run-id", "", "run id written into the record (default: <feature>-<UTC timestamp>)")
	c.Flags().StringVar(&vtEvidenceOperator, "evidence-operator", "", "operator named in the record (default: the current user)")
}

// evidenceSession collects what the chain does and writes the record at the
// end. A nil session is valid and records nothing, so the chain code calls it
// unconditionally.
type evidenceSession struct {
	mu            sync.Mutex
	path          string
	root          string
	rec           *evidence.Record
	outputs       map[string]string
	stdoutOutputs map[string]string
	playbooks     []string
	specs         []string
	extraArgs     []string
	inputs        []string
	sources       []evidence.SecretSource
	skipped       []string
	expected      []string
}

// newEvidenceSession returns nil when --evidence-record is unset.
func newEvidenceSession(playbooks, specs, extraArgs, expectedSteps []string, inputs ...string) (*evidenceSession, error) {
	if vtEvidenceRecord == "" {
		return nil, nil
	}
	root, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	path, err := filepath.Abs(vtEvidenceRecord)
	if err != nil {
		return nil, err
	}
	if filepath.Ext(path) != ".md" {
		return nil, fmt.Errorf("--evidence-record must name a Markdown file, got %s", vtEvidenceRecord)
	}
	feature := filepath.Base(filepath.Dir(path))
	now := time.Now().UTC()
	runID := vtEvidenceRunID
	if runID == "" {
		runID = feature + "-" + now.Format("20060102T150405Z")
	}
	operator := vtEvidenceOperator
	if operator == "" {
		if u, err := user.Current(); err == nil {
			operator = u.Username
		}
	}
	candidate := evidence.DetectCandidate(root)
	if vtEvidenceCandidate != "" || vtEvidenceTree != "" {
		sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
		if !sha.MatchString(vtEvidenceCandidate) || !sha.MatchString(vtEvidenceTree) {
			return nil, fmt.Errorf("--evidence-candidate and --evidence-tree must both be full 40-hex ids")
		}
		if candidate.Source == "git" && candidate.Commit != vtEvidenceCandidate {
			return nil, fmt.Errorf("--evidence-candidate %s does not match the checkout's HEAD %s", vtEvidenceCandidate[:12], candidate.Commit[:12])
		}
		if candidate.Source == "git" && candidate.Tree != vtEvidenceTree {
			return nil, fmt.Errorf("--evidence-tree does not match the checkout's HEAD tree")
		}
		note := ""
		if candidate.Source == "git" {
			note = candidate.Note
		}
		candidate = evidence.Candidate{Commit: vtEvidenceCandidate, Tree: vtEvidenceTree, Source: "flag", Dirty: candidate.Dirty, Note: note}
	}
	closure, err := evidence.ComputeClosure(evidence.ClosureInput{Root: root, Playbooks: playbooks, Specs: specs, ExtraArgs: extraArgs, Inputs: inputs})
	if err != nil {
		return nil, fmt.Errorf("freeze execution closure before run: %w", err)
	}
	sources, skipped := evidence.SecretSources(root, extraArgs)
	rec := &evidence.Record{
		Closure:     closure,
		Schema:      evidence.Schema,
		Feature:     feature,
		RunID:       runID,
		GeneratedBy: "pilot " + rootCmd.Version + " " + strings.Join(os.Args[1:3], " ") + " --evidence-record",
		Command:     evidence.RedactCommandLine(append([]string{"pilot"}, os.Args[1:]...)),
		Operator:    operator,
		StartedAt:   now,
		Candidate:   candidate,
		Tooling:     map[string]string{},
	}
	return &evidenceSession{path: path, root: root, rec: rec, outputs: map[string]string{}, stdoutOutputs: map[string]string{},
		playbooks: playbooks, specs: specs, extraArgs: extraArgs, inputs: inputs, sources: sources, skipped: skipped, expected: expectedSteps}, nil
}

// step runs fn with a writer that also captures the step's output, and
// records the step's status and duration. With a nil session it just runs fn.
func (s *evidenceSession) step(name string, out io.Writer, fn func(io.Writer) error) error {
	return s.stepStreams(name, out, io.Discard, func(stdout, _ io.Writer) error { return fn(stdout) })
}

type evidenceCaptureWriter struct {
	mu      *sync.Mutex
	capture *strings.Builder
	output  io.Writer
}

func (w evidenceCaptureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// stdout and stderr copy concurrently in os/exec. Serialize both the shared
	// capture and downstream destinations, preserving their distinct channels.
	w.capture.Write(p)
	return w.output.Write(p)
}

func (s *evidenceSession) stepStreams(name string, stdout, stderr io.Writer, fn func(io.Writer, io.Writer) error) error {
	if s == nil {
		return fn(stdout, stderr)
	}
	var stdoutBuf, stderrBuf strings.Builder
	var captureMu sync.Mutex
	start := time.Now()
	err := fn(evidenceCaptureWriter{&captureMu, &stdoutBuf, stdout}, evidenceCaptureWriter{&captureMu, &stderrBuf, stderr})
	s.mu.Lock()
	defer s.mu.Unlock()
	// Scan contiguous per-channel bytes: interleaving stderr must not split a
	// secret emitted across multiple stdout writes (or vice versa).
	s.outputs[name] += stdoutBuf.String() + "\n" + stderrBuf.String()
	s.stdoutOutputs[name] += stdoutBuf.String()
	st := evidence.Step{Name: name, Status: "pass", StartedAt: start.UTC(), DurationSeconds: time.Since(start).Seconds()}
	if err != nil {
		st.Status = "fail"
		st.Note = firstLine(err.Error())
	}
	if recap, ok := evidence.ParseRecap(stdoutBuf.String()); ok {
		st.Recap = recap
	}
	s.rec.Steps = append(s.rec.Steps, st)
	return err
}

// output returns the captured output of a step so far ("" for a nil session).
func (s *evidenceSession) output(name string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outputs[name]
}

// stdoutOutput is used only for semantic parsers; stderr is scanned separately.
func (s *evidenceSession) stdoutOutput(name string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stdoutOutputs[name]
}

// verify records one `pilot verify` run from its captured output.
func (s *evidenceSession) verify(spec, limit, output string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := evidence.VerifyResult{Spec: spec, Limit: limit}
	if verdict, ok := evidence.ParseVerifyVerdict(output); ok {
		v.VerifyVerdict = verdict
	}
	s.rec.Verify = append(s.rec.Verify, v)
}

// targets records the VMs and the rendered inventory.
func (s *evidenceSession) targets(targets []evidence.Target, inventoryYAML string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.Targets = targets
	s.rec.Inventory = evidence.ParseInventoryYAML(inventoryYAML)
	s.rec.Inventory.Source = "rendered by pilot for this run"
}

// finish completes the record and writes it. It never replaces the chain's
// error: a record that cannot be written is reported on stderr.
func (s *evidenceSession) finish(out, errOut io.Writer, outcome string, chainErr error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rec
	r.FinishedAt = time.Now().UTC()
	r.Outcome = outcome
	if chainErr != nil {
		r.Error = firstLine(chainErr.Error())
		for _, st := range r.Steps {
			if st.Status == "fail" && r.FailedStep == "" {
				r.FailedStep = st.Name
			}
		}
	}
	seen := map[string]bool{}
	for _, st := range r.Steps {
		seen[st.Name] = true
	}
	for _, name := range s.expected {
		if !seen[name] {
			r.Steps = append(r.Steps, evidence.Step{Name: name, Status: "not-run"})
		}
	}
	if exe, err := os.Executable(); err == nil {
		r.PilotBinary.Path = exe
		if sum, err := evidence.SHA256File(exe); err == nil {
			r.PilotBinary.SHA256 = sum
		}
		r.PilotBinary.Version = rootCmd.Version
	}
	if v, err := exec.Command("ansible-playbook", "--version").Output(); err == nil {
		r.Tooling["ansible-playbook"] = firstLine(string(v))
	}
	for i := range r.Targets {
		if r.Targets[i].BaseImage != "" && r.Targets[i].BaseImageSHA256 == "" {
			if sum, err := evidence.SHA256File(r.Targets[i].BaseImage); err == nil {
				r.Targets[i].BaseImageSHA256 = sum
			} else {
				r.Targets[i].Note = "base image not hashed: " + err.Error()
			}
		}
	}
	closure, err := evidence.ComputeClosure(evidence.ClosureInput{Root: s.root, Playbooks: s.playbooks, Specs: s.specs, ExtraArgs: s.extraArgs, Inputs: s.inputs})
	if err != nil || !reflect.DeepEqual(closure, r.Closure) {
		// Retain the pre-run hashes: post-run bytes are not what was tested.
		r.Closure.Unresolved = append(r.Closure.Unresolved, evidence.Reference{From: "execution closure", Ref: "run inputs", Reason: "execution inputs changed during the run or could not be rechecked"})
		r.Outcome = "invalid-inputs"
		fmt.Fprintln(errOut, "⚠️ evidence record: execution inputs changed during the run; evidence is not reusable")
	}
	if r.Outcome != "invalid-inputs" {
		r.Closure.Frozen = true
	}
	r.Redaction = evidence.Redact(s.outputs, s.sources, s.skipped)
	if err := evidence.SanitizeRecord(r, s.sources); err != nil {
		fmt.Fprintf(errOut, "⚠️ evidence record metadata could not be sanitized: %v\n", err)
		return
	}

	if err := r.Publish(s.path); err != nil {
		fmt.Fprintf(errOut, "⚠️ evidence publication failed for %s: %v\n", s.path, err)
		return
	}
	fmt.Fprintf(out, "📄 Evidence record written: %s (candidate %s, outcome %s)\n", s.path, shortSHA(r.Candidate.Commit), r.Outcome)
	if len(r.Redaction.Hits) > 0 {
		fmt.Fprintf(errOut, "⚠️ evidence record: %d secret value hit(s) in the captured output; do not commit the raw output (see the Redaction section)\n", len(r.Redaction.Hits))
	}
	if len(r.Redaction.Skipped) > 0 {
		fmt.Fprintln(errOut, "⚠️ evidence record: redaction scan INCOMPLETE; some supplied inputs were not scanned (see the Redaction section)")
	}
	if r.Candidate.Source == "unknown" {
		fmt.Fprintf(errOut, "⚠️ evidence record: tested revision unknown (%s); no gate will accept it\n", r.Candidate.Note)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func shortSHA(s string) string {
	if len(s) >= 12 {
		return s[:12]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// Include semantic validation in the recorded step: rc=0 alone is insufficient.
func runRecordedIdempotency(sess *evidenceSession, out io.Writer, run func(io.Writer) error) error {
	return runRecordedIdempotencyStreams(sess, out, io.Discard, func(stdout, _ io.Writer) error { return run(stdout) })
}

func runRecordedIdempotencyStreams(sess *evidenceSession, out, errOut io.Writer, run func(io.Writer, io.Writer) error) error {
	return sess.stepStreams("L6 idempotency", out, errOut, func(w, ew io.Writer) error {
		var captured strings.Builder
		if err := run(io.MultiWriter(w, &captured), ew); err != nil {
			return fmt.Errorf("idempotency run failed: %w", err)
		}
		changed, ok := idempotencyChangedCount(captured.String())
		if !ok {
			return fmt.Errorf("idempotency check: no PLAY RECAP found in ansible output (unable to confirm changed=0)")
		}
		if changed > 0 {
			return fmt.Errorf("idempotency check failed: playbook reported %d changed task(s) on second run", changed)
		}
		return nil
	})
}
