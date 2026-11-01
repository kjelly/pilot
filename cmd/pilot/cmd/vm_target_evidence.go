package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	mu        sync.Mutex
	path      string
	root      string
	rec       *evidence.Record
	outputs   map[string]string
	playbooks []string
	specs     []string
	extraArgs []string
	expected  []string
}

// newEvidenceSession returns nil when --evidence-record is unset.
func newEvidenceSession(playbooks, specs, extraArgs, expectedSteps []string) (*evidenceSession, error) {
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
		if len(vtEvidenceCandidate) != 40 || len(vtEvidenceTree) != 40 {
			return nil, fmt.Errorf("--evidence-candidate and --evidence-tree must both be full 40-hex ids")
		}
		if candidate.Source == "git" && candidate.Commit != vtEvidenceCandidate {
			return nil, fmt.Errorf("--evidence-candidate %s does not match the checkout's HEAD %s", vtEvidenceCandidate[:12], candidate.Commit[:12])
		}
		candidate = evidence.Candidate{Commit: vtEvidenceCandidate, Tree: vtEvidenceTree, Source: "flag"}
	}
	rec := &evidence.Record{
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
	return &evidenceSession{path: path, root: root, rec: rec, outputs: map[string]string{},
		playbooks: playbooks, specs: specs, extraArgs: extraArgs, expected: expectedSteps}, nil
}

// step runs fn with a writer that also captures the step's output, and
// records the step's status and duration. With a nil session it just runs fn.
func (s *evidenceSession) step(name string, out io.Writer, fn func(io.Writer) error) error {
	if s == nil {
		return fn(out)
	}
	var buf strings.Builder
	start := time.Now()
	err := fn(io.MultiWriter(out, &buf))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outputs[name] += buf.String()
	st := evidence.Step{Name: name, Status: "pass", StartedAt: start.UTC(), DurationSeconds: time.Since(start).Seconds()}
	if err != nil {
		st.Status = "fail"
		st.Note = firstLine(err.Error())
	}
	if recap, ok := evidence.ParseRecap(buf.String()); ok {
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
			if st.Status == "fail" {
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
	closure, err := evidence.ComputeClosure(evidence.ClosureInput{Root: s.root, Playbooks: s.playbooks, Specs: s.specs, ExtraArgs: s.extraArgs})
	if err != nil {
		fmt.Fprintf(errOut, "⚠️ evidence record: execution closure not computed: %v\n", err)
	} else {
		r.Closure = closure
	}
	sources, skipped := evidence.SecretSources(s.root, s.extraArgs)
	r.Redaction = evidence.Redact(s.outputs, sources, skipped)
	if err := r.WriteFile(s.path); err != nil {
		fmt.Fprintf(errOut, "⚠️ evidence record not written to %s: %v\n", s.path, err)
		return
	}
	fmt.Fprintf(out, "📄 Evidence record written: %s (candidate %s, outcome %s)\n", s.path, shortSHA(r.Candidate.Commit), outcome)
	if len(r.Redaction.Hits) > 0 {
		fmt.Fprintf(errOut, "⚠️ evidence record: %d secret value hit(s) in the captured output; do not commit the raw output (see the Redaction section)\n", len(r.Redaction.Hits))
	}
	if r.Candidate.Source == "unknown" {
		fmt.Fprintf(errOut, "⚠️ evidence record: tested revision unknown (%s); no gate will accept it\n", r.Candidate.Note)
	}
	if outcome == "success" {
		if err := evidence.UpdateLatest(filepath.Dir(s.path), r, s.path); err != nil {
			fmt.Fprintf(errOut, "⚠️ evidence record: LATEST.md not updated: %v\n", err)
		}
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
