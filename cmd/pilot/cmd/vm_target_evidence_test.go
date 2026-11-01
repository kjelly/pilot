package cmd

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/evidence"
)

// copyFixtureTree copies internal/evidence/testdata/closure into a fresh git
// repository with one commit, so the record has a real candidate.
func copyFixtureTree(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := filepath.Join(repoRootForTest(t), "internal", "evidence", "testdata", "closure")
	root := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		dst := filepath.Join(root, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, info.Mode())
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"config", "user.email", "t@example.org"}, {"config", "user.name", "t"}, {"add", "."}, {"commit", "--quiet", "-m", "candidate"}} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return root
}

func withEvidenceFlags(t *testing.T, record string) {
	t.Helper()
	old := []string{vtEvidenceRecord, vtEvidenceCandidate, vtEvidenceTree, vtEvidenceRunID, vtEvidenceOperator}
	vtEvidenceRecord, vtEvidenceCandidate, vtEvidenceTree, vtEvidenceRunID, vtEvidenceOperator = record, "", "", "run-1", "tester"
	t.Cleanup(func() {
		vtEvidenceRecord, vtEvidenceCandidate, vtEvidenceTree, vtEvidenceRunID, vtEvidenceOperator = old[0], old[1], old[2], old[3], old[4]
	})
}

const fakeApplyOutput = `PLAY [demo] ***
TASK [Render config] ***
changed: [d]

PLAY RECAP *********************************************************************
d                          : ok=9    changed=2    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
`

func TestEvidenceSessionWritesARecordAndLatest(t *testing.T) {
	root := copyFixtureTree(t)
	t.Chdir(root)
	record := filepath.Join(root, "docs", "evidence", "demo", "issue-7.md")
	withEvidenceFlags(t, record)
	extra := []string{"-e", "@vaultdir/sandbox.yaml", "-e", "target_group=demo", "-e", "api_token=tok-0123456789"}
	sess, err := newEvidenceSession([]string{"playbooks/site.yml"}, []string{"docs/verification/demo.md"}, extra, vtTestEvidenceSteps)
	if err != nil {
		t.Fatal(err)
	}
	if sess == nil {
		t.Fatal("session must exist when --evidence-record is set")
	}
	image := filepath.Join(root, "alma9.qcow2")
	if err := os.WriteFile(image, []byte("not really an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	sess.targets([]evidence.Target{{Name: "d", Groups: []string{"demo"}, IP: "192.168.123.9", BaseImage: image}}, "all:\n  hosts:\n    d:\n      ansible_host: 192.168.123.9\n  children:\n    demo:\n      hosts:\n        d: {}\n")
	var seen strings.Builder
	if err := sess.step("L1 syntax check", &seen, func(w io.Writer) error { _, err := io.WriteString(w, "playbook: ok\n"); return err }); err != nil {
		t.Fatal(err)
	}
	if err := sess.step("L4 apply", &seen, func(w io.Writer) error { _, err := io.WriteString(w, fakeApplyOutput); return err }); err != nil {
		t.Fatal(err)
	}
	if err := sess.step("L5 verify", &seen, func(w io.Writer) error {
		_, err := io.WriteString(w, "row C1 PASS\nverdict: **PASS**  (pass=1 fail=0 skip=0)\n")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sess.verify("docs/verification/demo.md", "demo", sess.output("L5 verify"))
	if !strings.Contains(seen.String(), "PLAY RECAP") || !strings.Contains(seen.String(), "verdict:") {
		t.Fatal("step must still write to the caller's writer")
	}
	var out, errOut strings.Builder
	sess.finish(&out, &errOut, "success", nil)
	if !strings.Contains(out.String(), "Evidence record written") {
		t.Fatalf("stdout = %q stderr = %q", out.String(), errOut.String())
	}
	doc, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := evidence.ParseMachineBlock(doc)
	if err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	if r.Feature != "demo" || r.RunID != "run-1" || r.Operator != "tester" || r.Outcome != "success" {
		t.Fatalf("header = %+v", r)
	}
	if r.Candidate.Source != "git" || len(r.Candidate.Commit) != 40 || r.Candidate.Dirty {
		t.Fatalf("candidate = %+v", r.Candidate)
	}
	steps := map[string]evidence.Step{}
	for _, s := range r.Steps {
		steps[s.Name] = s
	}
	if steps["L4 apply"].Status != "pass" || steps["L4 apply"].Recap["d"].Changed != 2 {
		t.Fatalf("L4 = %+v", steps["L4 apply"])
	}
	for _, notRun := range []string{"L3 check-mode dry-run", "L6 idempotency"} {
		if steps[notRun].Status != "not-run" {
			t.Fatalf("%s should be not-run: %+v", notRun, steps[notRun])
		}
	}
	if len(r.Verify) != 1 || r.Verify[0].Verdict != "PASS" || r.Verify[0].Pass != 1 || r.Verify[0].Limit != "demo" {
		t.Fatalf("verify = %+v", r.Verify)
	}
	if r.Targets[0].BaseImageSHA256 != evidence.SHA256Hex([]byte("not really an image")) || r.Inventory.Groups["demo"][0] != "d" {
		t.Fatalf("targets = %+v inventory = %+v", r.Targets, r.Inventory)
	}
	if r.PilotBinary.SHA256 == "" {
		t.Fatal("pilot binary not hashed")
	}
	var paths []string
	for _, f := range r.Closure.Files {
		paths = append(paths, f.Path)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"playbooks/site.yml", "playbooks/apply/demo-apply.yml", "playbooks/apply/tasks/helpers-inner.yml", "docs/verification/demo.md", "contracts/demo.yaml", "vaultdir/sandbox.yaml"} {
		if !strings.Contains(joined, want) {
			t.Errorf("closure lacks %s: %v", want, paths)
		}
	}
	if r.Redaction.Sources != 2 || len(r.Redaction.Hits) != 0 {
		t.Fatalf("redaction = %+v", r.Redaction)
	}
	latest, err := os.ReadFile(filepath.Join(root, "docs", "evidence", "demo", "LATEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(latest), "[issue-7.md](issue-7.md)") || !strings.Contains(string(latest), r.Candidate.Commit) {
		t.Fatalf("LATEST.md:\n%s", latest)
	}
	// The record names the secret-named keys it scanned for, never a value.
	if !strings.Contains(string(doc), "-e api_token") || strings.Contains(string(doc), "tok-0123456789") || strings.Contains(string(doc), "Sup3rS3cretPw!") {
		t.Fatal("the record must name the scanned keys and never carry a secret value")
	}
}

func TestEvidenceSessionFailureRecordsTheStepAndSkipsLatest(t *testing.T) {
	root := copyFixtureTree(t)
	t.Chdir(root)
	record := filepath.Join(root, "docs", "evidence", "demo", "issue-7.md")
	withEvidenceFlags(t, record)
	sess, err := newEvidenceSession([]string{"playbooks/site.yml"}, []string{"docs/verification/demo.md"}, []string{"-e", "@vaultdir/sandbox.yaml"}, vtTestEvidenceSteps)
	if err != nil {
		t.Fatal(err)
	}
	var sink strings.Builder
	leak := "TASK [kinit]\nfatal: [d]: FAILED! => {\"stdin\": \"Sup3rS3cretPw!\"}\n\nPLAY RECAP ****\nd : ok=3 changed=1 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n"
	_ = sess.step("L4 apply", &sink, func(w io.Writer) error { io.WriteString(w, leak); return io.ErrUnexpectedEOF })
	_ = sess.step("rollback", &sink, func(io.Writer) error { return nil })
	var out, errOut strings.Builder
	sess.finish(&out, &errOut, "rolled_back", io.ErrUnexpectedEOF)
	doc, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := evidence.ParseMachineBlock(doc)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "rolled_back" || r.FailedStep != "L4 apply" || r.Error == "" {
		t.Fatalf("outcome = %+v", r)
	}
	if len(r.Redaction.Hits) != 1 || r.Redaction.Hits[0].Step != "L4 apply" {
		t.Fatalf("the leaked password must be reported: %+v", r.Redaction)
	}
	if strings.Contains(string(doc), "Sup3rS3cretPw!") {
		t.Fatal("the record must not contain the secret value")
	}
	if !strings.Contains(errOut.String(), "secret value hit") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "evidence", "demo", "LATEST.md")); !os.IsNotExist(err) {
		t.Fatal("LATEST.md must not be written for a failed run")
	}
}

func TestEvidenceSessionFlagValidation(t *testing.T) {
	root := copyFixtureTree(t)
	t.Chdir(root)
	withEvidenceFlags(t, filepath.Join(root, "docs", "evidence", "demo", "notes.txt"))
	if _, err := newEvidenceSession([]string{"playbooks/site.yml"}, nil, nil, nil); err == nil {
		t.Fatal("a non-Markdown record path must be refused")
	}
	withEvidenceFlags(t, filepath.Join(root, "docs", "evidence", "demo", "r.md"))
	vtEvidenceCandidate, vtEvidenceTree = strings.Repeat("1", 40), strings.Repeat("2", 40)
	if _, err := newEvidenceSession([]string{"playbooks/site.yml"}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "does not match the checkout's HEAD") {
		t.Fatalf("a candidate flag that contradicts HEAD must be refused: %v", err)
	}
	vtEvidenceCandidate, vtEvidenceTree = strings.Repeat("1", 40), ""
	if _, err := newEvidenceSession([]string{"playbooks/site.yml"}, nil, nil, nil); err == nil {
		t.Fatal("candidate without tree must be refused")
	}
	candidate := evidence.DetectCandidate(root)
	vtEvidenceCandidate, vtEvidenceTree = candidate.Commit, strings.Repeat("z", 40)
	if _, err := newEvidenceSession(nil, nil, nil, nil); err == nil {
		t.Fatal("non-hex tree must be refused")
	}
	vtEvidenceTree = strings.Repeat("0", 40)
	if _, err := newEvidenceSession(nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "HEAD tree") {
		t.Fatalf("a contradictory tree must be refused: %v", err)
	}
	vtEvidenceTree = candidate.Tree
	if err := os.WriteFile(filepath.Join(root, "playbooks", "site.yml"), []byte("# modified during development\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flagged, err := newEvidenceSession(nil, nil, nil, nil)
	if err != nil || !flagged.rec.Candidate.Dirty {
		t.Fatalf("explicit candidate flags must preserve dirty status: %v", err)
	}
	vtEvidenceRecord, vtEvidenceCandidate, vtEvidenceTree = "", "", ""
	if sess, err := newEvidenceSession(nil, nil, nil, nil); err != nil || sess != nil {
		t.Fatalf("no flag, no session: %v %v", sess, err)
	}
	var sess *evidenceSession
	ran := false
	if err := sess.step("x", io.Discard, func(io.Writer) error { ran = true; return nil }); err != nil || !ran {
		t.Fatal("a nil session must still run the step")
	}
	sess.finish(io.Discard, io.Discard, "success", nil)
}
