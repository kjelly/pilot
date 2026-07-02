package store

import (
	"path/filepath"
	"testing"
)

func TestCheckpointUpsertAndList(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Need a run to satisfy proposals FK if we ever wire that — checkpoints
	// are independent so we can skip.
	cp := &Checkpoint{
		SpecPath:  "docs/verification/bastion.md",
		RowID:     "C2",
		RunID:     "run-1",
		TaskIndex: 3,
		Module:    "ansible.builtin.lineinfile",
		ParamHash: "abc123",
		Status:    "compiled",
	}
	if err := s.UpsertCheckpoint(cp); err != nil {
		t.Fatalf("UpsertCheckpoint: %v", err)
	}
	// Upsert again with same key but new status — should update in place.
	cp.Status = "verified-pass"
	cp.VerifyDetail = "got=PermitRootLogin no"
	if err := s.UpsertCheckpoint(cp); err != nil {
		t.Fatalf("UpsertCheckpoint 2: %v", err)
	}

	got, err := s.ListCheckpoints("docs/verification/bastion.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d checkpoints want=1", len(got))
	}
	if got[0].Status != "verified-pass" {
		t.Errorf("status=%q", got[0].Status)
	}
	if got[0].VerifyDetail != "got=PermitRootLogin no" {
		t.Errorf("detail=%q", got[0].VerifyDetail)
	}
}

func TestProposalResultRecordAndList(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r1 := &ProposalResult{ProposalID: "p1", CheckID: "C1", Host: "host-a", Status: "pass", Detail: "exists"}
	if err := s.RecordProposalResult(r1); err != nil {
		t.Fatal(err)
	}
	// Re-record with new status — must upsert.
	r2 := &ProposalResult{ProposalID: "p1", CheckID: "C1", Host: "host-a", Status: "fail", Detail: "missing"}
	if err := s.RecordProposalResult(r2); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListProposalResults("p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Status != "fail" {
		t.Fatalf("results=%+v", got)
	}
}
